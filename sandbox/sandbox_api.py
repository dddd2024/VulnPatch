#!/usr/bin/env python3
"""
VulnScan Sandbox Service API
==============================
Independent sandbox service for PoC execution and vulnerability verification.
Provides isolated, resource-constrained execution environments using Docker-in-Docker.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import docker
import httpx
import psutil
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ============================================
# Configuration
# ============================================
class Settings:
    """Sandbox service configuration from environment variables."""
    API_PORT: int = int(os.getenv("SANDBOX_API_PORT", "8001"))
    MAX_EXECUTION_TIME: int = int(os.getenv("MAX_EXECUTION_TIME", "300"))  # seconds
    MAX_MEMORY_MB: int = int(os.getenv("MAX_MEMORY_MB", "512"))  # MB
    MAX_CPU_PERCENT: float = float(os.getenv("MAX_CPU_PERCENT", "50.0"))  # percent
    DOCKER_HOST: str = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    SANDBOX_TMP_DIR: Path = Path(os.getenv("SANDBOX_TMP_DIR", "/tmp/sandbox"))
    SECCOMP_PROFILE: Path = Path(os.getenv("SECCOMP_PROFILE", "/opt/sandbox/seccomp-profile.json"))
    BACKEND_API_URL: str = os.getenv("BACKEND_API_URL", "http://backend:8000")
    BACKEND_API_KEY: str = os.getenv("BACKEND_API_KEY", "")
    MAX_CONCURRENT_JOBS: int = int(os.getenv("MAX_CONCURRENT_JOBS", "10"))
    CONTAINER_IMAGE: str = os.getenv("CONTAINER_IMAGE", "python:3.11-slim")
    NETWORK_MODE: str = os.getenv("NETWORK_MODE", "none")  # none = isolated


settings = Settings()

# ============================================
# Logging
# ============================================
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sandbox")

# ============================================
# Job Tracking
# ============================================
class JobStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class JobInfo:
    def __init__(self, job_id: str, job_type: str):
        self.job_id = job_id
        self.job_type = job_type
        self.status = JobStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.container_id: Optional[str] = None
        self.resource_usage: Dict[str, Any] = {}


# In-memory job store (use Redis in production)
_jobs: Dict[str, JobInfo] = {}
_job_semaphore: Optional[asyncio.Semaphore] = None
_docker_client: Optional[docker.DockerClient] = None

# ============================================
# Pydantic Models
# ============================================
class ExecuteRequest(BaseModel):
    """Request model for executing PoC code."""
    code: str = Field(..., min_length=1, description="PoC code to execute")
    language: str = Field(default="python", description="Programming language")
    timeout: Optional[int] = Field(default=None, ge=1, le=1800, description="Execution timeout in seconds")
    inputs: Optional[Dict[str, Any]] = Field(default=None, description="Input parameters for the PoC")
    target: Optional[str] = Field(default=None, description="Target URL/IP for the PoC")
    env_vars: Optional[Dict[str, str]] = Field(default=None, description="Environment variables")
    network_enabled: bool = Field(default=False, description="Enable network access in sandbox")
    memory_limit_mb: Optional[int] = Field(default=None, ge=64, le=4096)
    cpu_limit_percent: Optional[float] = Field(default=None, ge=1, le=100)

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        allowed = {"python", "javascript", "java", "go", "c", "cpp", "bash", "sh"}
        if v.lower() not in allowed:
            raise ValueError(f"Unsupported language: {v}. Allowed: {allowed}")
        return v.lower()


class VerifyRequest(BaseModel):
    """Request model for vulnerability verification."""
    vuln_id: str = Field(..., description="Vulnerability ID")
    target: str = Field(..., description="Target to verify")
    poc_code: str = Field(..., description="PoC code for verification")
    language: str = Field(default="python", description="Programming language")
    verification_method: str = Field(default="active", description="Verification method")
    timeout: Optional[int] = Field(default=None, ge=1, le=1800)
    expected_result: Optional[str] = Field(default=None, description="Expected result pattern")

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        allowed = {"python", "javascript", "java", "go", "c", "cpp", "bash", "sh"}
        if v.lower() not in allowed:
            raise ValueError(f"Unsupported language: {v}. Allowed: {allowed}")
        return v.lower()

    @field_validator("verification_method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        allowed = {"active", "passive", "hybrid"}
        if v.lower() not in allowed:
            raise ValueError(f"Unsupported method: {v}. Allowed: {allowed}")
        return v.lower()


class JobResponse(BaseModel):
    """Response model for job submission."""
    job_id: str
    status: str
    message: str
    estimated_duration: int


class JobResultResponse(BaseModel):
    """Response model for job result."""
    job_id: str
    status: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    resource_usage: Optional[Dict[str, Any]] = None


class SandboxStatus(BaseModel):
    """Response model for sandbox status."""
    status: str
    uptime_seconds: float
    active_jobs: int
    total_jobs: int
    system_resources: Dict[str, Any]
    docker_available: bool
    version: str


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    timestamp: str
    version: str
    docker_connected: bool
    disk_usage_percent: float
    memory_usage_percent: float


# ============================================
# Docker Client Management
# ============================================
def get_docker_client() -> docker.DockerClient:
    """Get or create Docker client."""
    global _docker_client
    if _docker_client is None:
        try:
            _docker_client = docker.DockerClient(base_url=settings.DOCKER_HOST)
            _docker_client.ping()
            logger.info("Docker client connected successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            raise RuntimeError(f"Docker connection failed: {e}")
    return _docker_client


# ============================================
# Code Execution Engine
# ============================================
def prepare_code_file(code: str, language: str, work_dir: Path) -> Path:
    """Prepare code file based on language."""
    extensions = {
        "python": "script.py",
        "javascript": "script.js",
        "java": "Main.java",
        "go": "main.go",
        "c": "main.c",
        "cpp": "main.cpp",
        "bash": "script.sh",
        "sh": "script.sh",
    }
    filename = extensions.get(language, "script.py")
    file_path = work_dir / filename
    file_path.write_text(code, encoding="utf-8")
    return file_path


def get_execution_command(language: str, file_path: Path) -> List[str]:
    """Get execution command for the given language."""
    commands = {
        "python": ["python3", str(file_path.name)],
        "javascript": ["node", str(file_path.name)],
        "java": ["sh", "-c", f"javac {file_path.name} && java Main"],
        "go": ["sh", "-c", f"go run {file_path.name}"],
        "c": ["sh", "-c", f"gcc {file_path.name} -o main && ./main"],
        "cpp": ["sh", "-c", f"g++ {file_path.name} -o main && ./main"],
        "bash": ["bash", str(file_path.name)],
        "sh": ["sh", str(file_path.name)],
    }
    return commands.get(language, ["python3", str(file_path.name)])


def get_sandbox_image(language: str) -> str:
    """Get appropriate sandbox Docker image for language."""
    images = {
        "python": "python:3.11-slim",
        "javascript": "node:20-slim",
        "java": "openjdk:17-slim",
        "go": "golang:1.22",
        "c": "gcc:13",
        "cpp": "gcc:13",
        "bash": "bash:5",
        "sh": "bash:5",
    }
    return images.get(language, settings.CONTAINER_IMAGE)


async def execute_in_container(
    job: JobInfo,
    code: str,
    language: str,
    timeout: int,
    network_enabled: bool,
    memory_limit_mb: int,
    cpu_limit_percent: float,
    env_vars: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Execute code in an isolated Docker container."""
    client = get_docker_client()
    work_dir = settings.SANDBOX_TMP_DIR / "jobs" / job.job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Prepare code file
        file_path = prepare_code_file(code, language, work_dir)
        cmd = get_execution_command(language, file_path)
        image = get_sandbox_image(language)

        # Pull image if not available
        try:
            client.images.get(image)
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image {image}...")
            client.images.pull(image)

        # Prepare environment variables
        container_env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
        if env_vars:
            container_env.update(env_vars)

        # Security options
        security_opt = []
        if settings.SECCOMP_PROFILE.exists():
            security_opt.append(f"seccomp={settings.SECCOMP_PROFILE}")

        # Resource limits
        mem_limit = f"{memory_limit_mb}m"
        cpu_quota = int(cpu_limit_percent * 1000)  # Docker uses microseconds
        cpu_period = 100000

        # Network configuration
        network_mode = "bridge" if network_enabled else settings.NETWORK_MODE

        # Run container
        logger.info(f"Starting container for job {job.job_id}")
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()

        container = client.containers.run(
            image=image,
            command=cmd,
            detach=True,
            working_dir="/workspace",
            volumes={str(work_dir): {"bind": "/workspace", "mode": "rw"}},
            environment=container_env,
            network_mode=network_mode,
            mem_limit=mem_limit,
            memswap_limit=mem_limit,
            cpu_quota=cpu_quota,
            cpu_period=cpu_period,
            security_opt=security_opt,
            cap_drop=["ALL"],
            cap_add=["CHOWN", "SETGID", "SETUID"] if language in ("c", "cpp", "go") else [],
            read_only=False,
            stdin_open=False,
            tty=False,
            auto_remove=False,
            labels={
                "vulnscan.sandbox.job_id": job.job_id,
                "vulnscan.sandbox.created": datetime.utcnow().isoformat(),
            },
        )
        job.container_id = container.id

        # Wait for completion with timeout
        start_time = time.time()
        result = {"stdout": "", "stderr": "", "exit_code": -1, "duration": 0}

        try:
            # Poll container status
            while time.time() - start_time < timeout:
                container.reload()
                if container.status == "exited":
                    break
                await asyncio.sleep(0.5)

            # Handle timeout
            if container.status != "exited":
                logger.warning(f"Job {job.job_id} timed out after {timeout}s")
                container.kill(signal="SIGKILL")
                job.status = JobStatus.TIMEOUT
                result["stderr"] = f"Execution timed out after {timeout} seconds"
                result["exit_code"] = -1
            else:
                # Get results
                logs = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                err_logs = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                inspect = container.wait()
                result["stdout"] = logs
                result["stderr"] = err_logs
                result["exit_code"] = inspect.get("StatusCode", -1)
                result["duration"] = round(time.time() - start_time, 2)
                job.status = JobStatus.COMPLETED if result["exit_code"] == 0 else JobStatus.FAILED

            # Get resource usage stats
            try:
                stats = container.stats(stream=False)
                if stats and "memory_stats" in stats:
                    mem_usage = stats["memory_stats"].get("usage", 0)
                    result["memory_peak_mb"] = round(mem_usage / (1024 * 1024), 2)
            except Exception as e:
                logger.debug(f"Could not get stats for job {job.job_id}: {e}")

        finally:
            # Cleanup container
            try:
                container.remove(force=True, v=True)
            except Exception as e:
                logger.warning(f"Failed to remove container for job {job.job_id}: {e}")

        job.result = result
        job.completed_at = datetime.utcnow()
        return result

    except Exception as e:
        logger.exception(f"Execution failed for job {job.job_id}")
        job.status = JobStatus.FAILED
        job.error = str(e)
        job.completed_at = datetime.utcnow()
        raise
    finally:
        # Cleanup work directory
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


# ============================================
# FastAPI Application
# ============================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global _job_semaphore
    _job_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_JOBS)

    # Initialize Docker client
    try:
        get_docker_client()
        logger.info("Sandbox service initialized successfully")
    except Exception as e:
        logger.warning(f"Docker not available: {e}")

    yield

    # Cleanup
    logger.info("Shutting down sandbox service...")


app = FastAPI(
    title="VulnScan Sandbox Service",
    description="Isolated execution environment for PoC code and vulnerability verification",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================
# Exception Handlers
# ============================================
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )


# ============================================
# API Endpoints
# ============================================
@app.post("/execute", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
async def execute_poc(request: ExecuteRequest):
    """
    Submit PoC code for execution in an isolated sandbox.
    Returns a job ID for tracking the execution.
    """
    job_id = str(uuid.uuid4())
    job = JobInfo(job_id=job_id, job_type="execute")
    _jobs[job_id] = job

    timeout = request.timeout or settings.MAX_EXECUTION_TIME
    memory_limit = request.memory_limit_mb or settings.MAX_MEMORY_MB
    cpu_limit = request.cpu_limit_percent or settings.MAX_CPU_PERCENT

    # Start execution in background
    async def run_job():
        async with _job_semaphore:
            try:
                await execute_in_container(
                    job=job,
                    code=request.code,
                    language=request.language,
                    timeout=timeout,
                    network_enabled=request.network_enabled,
                    memory_limit_mb=memory_limit,
                    cpu_limit_percent=cpu_limit,
                    env_vars=request.env_vars,
                )
                # Notify backend
                await notify_backend(job)
            except Exception as e:
                job.status = JobStatus.FAILED
                job.error = str(e)
                job.completed_at = datetime.utcnow()
                await notify_backend(job)

    asyncio.create_task(run_job())

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        message="PoC execution submitted",
        estimated_duration=min(timeout, settings.MAX_EXECUTION_TIME),
    )


@app.post("/verify", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
async def verify_vulnerability(request: VerifyRequest):
    """
    Submit vulnerability verification request.
    Executes PoC against target and checks for vulnerability confirmation.
    """
    job_id = str(uuid.uuid4())
    job = JobInfo(job_id=job_id, job_type="verify")
    _jobs[job_id] = job

    timeout = request.timeout or settings.MAX_EXECUTION_TIME

    # Build verification wrapper code
    wrapper_code = build_verification_wrapper(
        poc_code=request.poc_code,
        target=request.target,
        language=request.language,
        expected_result=request.expected_result,
    )

    async def run_verification():
        async with _job_semaphore:
            try:
                result = await execute_in_container(
                    job=job,
                    code=wrapper_code,
                    language=request.language,
                    timeout=timeout,
                    network_enabled=True,  # Verification needs network
                    memory_limit_mb=settings.MAX_MEMORY_MB,
                    cpu_limit_percent=settings.MAX_CPU_PERCENT,
                )
                # Analyze result for vulnerability confirmation
                is_vulnerable = analyze_verification_result(result, request.expected_result)
                result["vulnerable"] = is_vulnerable
                result["vuln_id"] = request.vuln_id
                result["target"] = request.target
                job.result = result
                await notify_backend(job)
            except Exception as e:
                job.status = JobStatus.FAILED
                job.error = str(e)
                job.completed_at = datetime.utcnow()
                await notify_backend(job)

    asyncio.create_task(run_verification())

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        message="Vulnerability verification submitted",
        estimated_duration=min(timeout, settings.MAX_EXECUTION_TIME),
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    docker_connected = False
    try:
        client = get_docker_client()
        client.ping()
        docker_connected = True
    except Exception:
        pass

    # System metrics
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return HealthResponse(
        status="healthy" if docker_connected else "degraded",
        timestamp=datetime.utcnow().isoformat(),
        version="1.0.0",
        docker_connected=docker_connected,
        disk_usage_percent=round(disk.percent, 1),
        memory_usage_percent=round(memory.percent, 1),
    )


@app.get("/status", response_model=SandboxStatus)
async def sandbox_status():
    """Get detailed sandbox status and resource usage."""
    docker_available = False
    try:
        client = get_docker_client()
        client.ping()
        docker_available = True
    except Exception:
        pass

    # System resources
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net_io = psutil.net_io_counters()

    active_jobs = sum(1 for j in _jobs.values() if j.status == JobStatus.RUNNING)

    return SandboxStatus(
        status="operational",
        uptime_seconds=time.time() - psutil.boot_time(),
        active_jobs=active_jobs,
        total_jobs=len(_jobs),
        system_resources={
            "cpu_percent": cpu_percent,
            "memory_total_mb": round(memory.total / (1024 * 1024), 0),
            "memory_used_mb": round(memory.used / (1024 * 1024), 0),
            "memory_percent": memory.percent,
            "disk_total_gb": round(disk.total / (1024 ** 3), 1),
            "disk_used_gb": round(disk.used / (1024 ** 3), 1),
            "disk_percent": disk.percent,
            "network_bytes_sent": net_io.bytes_sent,
            "network_bytes_recv": net_io.bytes_recv,
        },
        docker_available=docker_available,
        version="1.0.0",
    )


@app.get("/jobs/{job_id}", response_model=JobResultResponse)
async def get_job_result(job_id: str):
    """Get the result of a submitted job."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    return JobResultResponse(
        job_id=job.job_id,
        status=job.status,
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        result=job.result,
        error=job.error,
        resource_usage=job.resource_usage,
    )


@app.get("/jobs", response_model=List[JobResultResponse])
async def list_jobs(status_filter: Optional[str] = None, limit: int = 100):
    """List recent jobs with optional status filter."""
    jobs = list(_jobs.values())
    if status_filter:
        jobs = [j for j in jobs if j.status == status_filter]
    jobs = sorted(jobs, key=lambda j: j.created_at, reverse=True)[:limit]

    return [
        JobResultResponse(
            job_id=j.job_id,
            status=j.status,
            created_at=j.created_at.isoformat(),
            started_at=j.started_at.isoformat() if j.started_at else None,
            completed_at=j.completed_at.isoformat() if j.completed_at else None,
            result=j.result,
            error=j.error,
            resource_usage=j.resource_usage,
        )
        for j in jobs
    ]


@app.delete("/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a running job and clean up its container."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    if job.status != JobStatus.RUNNING:
        return {"message": f"Job {job_id} is not running (status: {job.status})"}

    # Kill container
    if job.container_id:
        try:
            client = get_docker_client()
            container = client.containers.get(job.container_id)
            container.kill(signal="SIGKILL")
            container.remove(force=True)
        except Exception as e:
            logger.warning(f"Failed to kill container for job {job_id}: {e}")

    job.status = JobStatus.CANCELLED
    job.completed_at = datetime.utcnow()
    return {"message": f"Job {job_id} cancelled"}


# ============================================
# Helper Functions
# ============================================
def build_verification_wrapper(
    poc_code: str,
    target: str,
    language: str,
    expected_result: Optional[str] = None,
) -> str:
    """Build wrapper code that runs PoC and captures result."""
    if language == "python":
        wrapper = f'''
import sys
import json
import subprocess
import os

# Set target environment variable
os.environ["TARGET"] = {repr(target)}
os.environ["VULN_TARGET"] = {repr(target)}

# Run the PoC
{poc_code}

# If we get here without exception, check output
print("[SANDBOX] Verification completed")
'''
    elif language == "javascript":
        wrapper = f'''
process.env.TARGET = {JSON.stringify(target)};
process.env.VULN_TARGET = {JSON.stringify(target)};

{poc_code}

console.log("[SANDBOX] Verification completed");
'''
    else:
        # Generic wrapper using environment variables
        wrapper = f'''
export TARGET={target}
export VULN_TARGET={target}

{poc_code}

echo "[SANDBOX] Verification completed"
'''
    return wrapper


def analyze_verification_result(result: Dict[str, Any], expected_result: Optional[str]) -> bool:
    """Analyze execution result to determine if vulnerability is present."""
    if result.get("exit_code", -1) != 0:
        return False

    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    combined = stdout + stderr

    # Check for expected result pattern
    if expected_result and expected_result in combined:
        return True

    # Common vulnerability indicators
    vuln_indicators = [
        "vulnerable", "exploit successful", "poc confirmed",
        "true positive", "vulnerability confirmed", "exploited",
    ]
    combined_lower = combined.lower()
    return any(ind in combined_lower for ind in vuln_indicators)


async def notify_backend(job: JobInfo):
    """Notify backend service of job completion."""
    if not settings.BACKEND_API_URL:
        return

    payload = {
        "job_id": job.job_id,
        "job_type": job.job_type,
        "status": job.status,
        "result": job.result,
        "error": job.error,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }

    headers = {}
    if settings.BACKEND_API_KEY:
        headers["X-API-Key"] = settings.BACKEND_API_KEY

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{settings.BACKEND_API_URL}/sandbox/callback",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            logger.info(f"Notified backend for job {job.job_id}")
    except Exception as e:
        logger.warning(f"Failed to notify backend for job {job.job_id}: {e}")


# ============================================
# Main Entry Point
# ============================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "sandbox_api:app",
        host="0.0.0.0",
        port=settings.API_PORT,
        workers=2,
        log_level=settings.LOG_LEVEL.lower(),
    )
