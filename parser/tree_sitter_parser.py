"""
Tree-sitter 多语言统一解析模块

提供跨语言的统一 AST 解析接口，支持：
- Python
- JavaScript / TypeScript
- Java
- Go
- PHP
- C / C++
- Rust

该模块作为现有 ast_parser.py 的扩展，不替代原有功能。
"""

from __future__ import annotations

import re
import os
from ctypes import CDLL
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Callable

try:
    from tree_sitter import Language, Parser, Tree
except ImportError:
    raise ImportError(
        "tree-sitter is not installed. Run: pip install tree-sitter"
    )


class LanguageType(Enum):
    """支持的编程语言枚举"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    PHP = "php"
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    UNKNOWN = "unknown"


# 文件扩展名到语言的映射
EXTENSION_TO_LANGUAGE: dict[str, LanguageType] = {
    ".py": LanguageType.PYTHON,
    ".js": LanguageType.JAVASCRIPT,
    ".jsx": LanguageType.JAVASCRIPT,
    ".ts": LanguageType.TYPESCRIPT,
    ".tsx": LanguageType.TYPESCRIPT,
    ".java": LanguageType.JAVA,
    ".go": LanguageType.GO,
    ".php": LanguageType.PHP,
    ".c": LanguageType.C,
    ".h": LanguageType.C,
    ".cpp": LanguageType.CPP,
    ".cc": LanguageType.CPP,
    ".cxx": LanguageType.CPP,
    ".rs": LanguageType.RUST,
}


def get_language_by_extension(ext: str) -> LanguageType:
    """根据文件扩展名获取语言类型"""
    return EXTENSION_TO_LANGUAGE.get(ext.lower(), LanguageType.UNKNOWN)


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    line: int
    end_line: int
    params: list[str] = field(default_factory=list)


@dataclass
class CallInfo:
    """函数调用信息"""
    caller: str | None  # None 表示模块级调用
    callee: str
    line: int


@dataclass
class RouteInfo:
    """路由信息（主要用于 Web 框架）"""
    path: str
    function: str
    line: int
    decorators: list[str] = field(default_factory=list)


@dataclass
class ParsedCode:
    """统一解析结果"""
    language: LanguageType
    file_path: str
    source: str
    tree: Tree
    functions: list[FunctionInfo] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    routes: list[RouteInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


class TreeSitterParser:
    """
    Tree-sitter 多语言统一解析器

    提供跨语言的 AST 解析、函数提取、调用关系分析等能力。
    """

    def __init__(self):
        """初始化解析器"""
        self._parsers: dict[LanguageType, Parser] = {}
        self._languages: dict[LanguageType, Language] = {}
        self._init_parsers()

    def _get_languages_dll_path(self) -> str:
        """获取 tree-sitter-languages DLL 路径"""
        try:
            import tree_sitter_languages
            lang_dir = os.path.dirname(tree_sitter_languages.__file__)
            dll_path = os.path.join(lang_dir, "languages.dll")
            if os.path.exists(dll_path):
                return dll_path
        except ImportError:
            pass

        # 尝试常见路径
        common_paths = [
            r"C:\Users\mazih\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\vm\tools\python\lib\site-packages\tree_sitter_languages\languages.dll",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path

        raise FileNotFoundError("Could not find tree-sitter-languages languages.dll")

    def _load_language(self, lang_name: str, lang_type: LanguageType) -> Language | None:
        """手动加载语言库"""
        try:
            dll_path = self._get_languages_dll_path()
            # 加载 DLL
            lib = CDLL(dll_path)

            # 使用 Language.from_cached_library 或类似方法
            # tree-sitter 0.25.x 新 API
            lang = Language(dll_path.encode(), lang_name.encode())
            return lang
        except Exception as e:
            print(f"Failed to load language {lang_name}: {e}")
            return None

    def _init_parsers(self) -> None:
        """初始化各语言解析器"""
        # 尝试使用 tree-sitter-languages
        try:
            from tree_sitter_languages import get_language, get_parser

            # 优先初始化的语言
            priority_langs = [
                (LanguageType.PYTHON, "python"),
                (LanguageType.JAVASCRIPT, "javascript"),
                (LanguageType.TYPESCRIPT, "typescript"),
                (LanguageType.JAVA, "java"),
                (LanguageType.GO, "go"),
                (LanguageType.PHP, "php"),
                (LanguageType.C, "c"),
                (LanguageType.CPP, "cpp"),
            ]

            for lang_type, lang_name in priority_langs:
                try:
                    self._languages[lang_type] = get_language(lang_name)
                    self._parsers[lang_type] = get_parser(lang_name)
                except Exception as e:
                    print(f"Failed to init {lang_name}: {e}")

            if self._parsers:
                print(f"Loaded {len(self._parsers)} languages via tree-sitter-languages")
                return

        except ImportError:
            pass

        # 回退：使用手动加载
        print("Trying manual language loading...")

        try:
            dll_path = self._get_languages_dll_path()
            lib = CDLL(dll_path)

            lang_mappings = [
                (LanguageType.PYTHON, "python"),
                (LanguageType.JAVASCRIPT, "javascript"),
            ]

            for lang_type, lang_name in lang_mappings:
                try:
                    lang = Language(dll_path.encode(), lang_name.encode())
                    parser = Parser(lang)
                    self._languages[lang_type] = lang
                    self._parsers[lang_type] = parser
                except Exception as e:
                    print(f"Manual load {lang_name} failed: {e}")

        except Exception as e:
            print(f"Manual loading failed: {e}")

    def get_parser(self, lang: LanguageType) -> Parser | None:
        """获取指定语言的解析器"""
        return self._parsers.get(lang)

    def is_language_supported(self, lang: LanguageType) -> bool:
        """检查语言是否支持"""
        return lang in self._parsers

    def parse_file(self, file_path: str) -> ParsedCode | None:
        """
        解析文件

        Args:
            file_path: 文件路径

        Returns:
            ParsedCode 对象，或 None 如果不支持该语言
        """
        path = Path(file_path)
        ext = path.suffix
        lang_type = get_language_by_extension(ext)

        if lang_type == LanguageType.UNKNOWN or lang_type not in self._parsers:
            return None

        source = path.read_text(encoding="utf-8")
        return self.parse(source, lang_type, file_path)

    def parse(
        self,
        source: str,
        lang_type: LanguageType,
        file_path: str = "<string>"
    ) -> ParsedCode | None:
        """
        解析代码字符串

        Args:
            source: 源代码
            lang_type: 语言类型
            file_path: 文件路径（用于错误信息）

        Returns:
            ParsedCode 对象，或 None 如果不支持该语言
        """
        if lang_type not in self._parsers:
            return None

        parser = self._parsers[lang_type]
        tree = parser.parse(source.encode("utf-8"))

        parsed = ParsedCode(
            language=lang_type,
            file_path=file_path,
            source=source,
            tree=tree,
        )

        # 根据语言提取信息
        if lang_type == LanguageType.PYTHON:
            self._extract_python_info(parsed)
        elif lang_type == LanguageType.JAVASCRIPT:
            self._extract_javascript_info(parsed)
        elif lang_type == LanguageType.TYPESCRIPT:
            self._extract_typescript_info(parsed)
        elif lang_type == LanguageType.JAVA:
            self._extract_java_info(parsed)
        elif lang_type == LanguageType.GO:
            self._extract_go_info(parsed)
        elif lang_type == LanguageType.PHP:
            self._extract_php_info(parsed)
        elif lang_type == LanguageType.C:
            self._extract_c_info(parsed)
        elif lang_type == LanguageType.CPP:
            self._extract_cpp_info(parsed)

        return parsed

    def _extract_python_info(self, parsed: ParsedCode) -> None:
        """提取 Python 代码信息"""
        root = parsed.tree.root_node

        # 查找所有函数定义
        for node in self._find_nodes(root, "function_definition"):
            name = self._get_func_name(node)
            if name:
                params = self._get_func_params(node, "python")
                line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                parsed.functions.append(FunctionInfo(name, line, end_line, params))

        # 查找所有函数调用
        for node in self._find_nodes(root, "call"):
            callee = self._get_call_name(node)
            if callee:
                caller = self._get_current_function(node, root)
                line = node.start_point[0] + 1
                parsed.calls.append(CallInfo(caller, callee, line))

        # 查找 import
        for node in self._find_nodes(root, "import_statement"):
            names = self._get_import_names(node)
            parsed.imports.extend(names)

        # 查找路由装饰器
        for node in self._find_nodes(root, "decorated_definition"):
            decos = self._get_decorators(node)
            for deco in decos:
                if "route" in deco or "app.route" in deco:
                    func_node = self._get_decorated_func(node)
                    if func_node:
                        func_name = self._get_func_name(func_node)
                        route_path = self._extract_route_path(deco)
                        if route_path and func_name:
                            parsed.routes.append(RouteInfo(route_path, func_name, func_node.start_point[0] + 1, decos))

    def _extract_javascript_info(self, parsed: ParsedCode) -> None:
        """提取 JavaScript 代码信息"""
        root = parsed.tree.root_node

        # 查找函数定义 (function declaration)
        for node in self._find_nodes(root, "function_declaration"):
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else None
            if name:
                params = self._get_func_params(node, "javascript")
                line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                parsed.functions.append(FunctionInfo(name, line, end_line, params))

        # 查找 Arrow function expressions (变量赋值形式)
        for node in self._find_nodes(root, "variable_declarator"):
            init = node.child_by_field_name("value")
            if init and init.type in ("arrow_function", "function"):
                name_node = node.child_by_field_name("name")
                name = name_node.text.decode() if name_node else None
                if name and isinstance(name, str):
                    line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    parsed.functions.append(FunctionInfo(name, line, end_line, []))

        # 查找函数调用
        for node in self._find_nodes(root, "call_expression"):
            callee = self._get_js_call_name(node)
            if callee:
                caller = self._get_current_function(node, root)
                line = node.start_point[0] + 1
                parsed.calls.append(CallInfo(caller, callee, line))

        # 查找 import
        for node in self._find_nodes(root, "import_statement"):
            names = self._get_js_import_names(node)
            parsed.imports.extend(names)

    def _extract_typescript_info(self, parsed: ParsedCode) -> None:
        """提取 TypeScript 代码信息（复用 JS 逻辑）"""
        self._extract_javascript_info(parsed)

    def _extract_java_info(self, parsed: ParsedCode) -> None:
        """提取 Java 代码信息"""
        root = parsed.tree.root_node

        # 查找方法定义
        for node in self._find_nodes(root, "method_declaration"):
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else None
            if name:
                params = self._get_java_params(node)
                line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                parsed.functions.append(FunctionInfo(name, line, end_line, params))

        # 查找类方法调用 - Java 使用 method_invocation 节点
        for node in self._find_nodes(root, "method_invocation"):
            callee = self._get_java_method_name(node)
            if callee:
                caller = self._get_current_function(node, root)
                line = node.start_point[0] + 1
                parsed.calls.append(CallInfo(caller, callee, line))

    def _extract_go_info(self, parsed: ParsedCode) -> None:
        """提取 Go 代码信息"""
        root = parsed.tree.root_node

        # 查找函数定义
        for node in self._find_nodes(root, "function_declaration"):
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else None
            if name:
                params = self._get_go_params(node)
                line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                parsed.functions.append(FunctionInfo(name, line, end_line, params))

        # 查找函数调用
        for node in self._find_nodes(root, "call_expression"):
            callee = self._get_call_name(node)
            if callee:
                caller = self._get_current_function(node, root)
                line = node.start_point[0] + 1
                parsed.calls.append(CallInfo(caller, callee, line))

    def _extract_php_info(self, parsed: ParsedCode) -> None:
        """提取 PHP 代码信息"""
        root = parsed.tree.root_node

        # 查找函数定义
        for node in self._find_nodes(root, "function_definition"):
            name_node = node.child_by_field_name("name")
            name = name_node.text.decode() if name_node else None
            if name:
                params = self._get_php_params(node)
                line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                parsed.functions.append(FunctionInfo(name, line, end_line, params))

        # 查找方法调用
        for node in self._find_nodes(root, "method_call"):
            callee = self._get_php_call_name(node)
            if callee:
                caller = self._get_current_function(node, root)
                line = node.start_point[0] + 1
                parsed.calls.append(CallInfo(caller, callee, line))

    def _extract_c_info(self, parsed: ParsedCode) -> None:
        """提取 C 代码信息"""
        root = parsed.tree.root_node

        # 查找函数定义
        for node in self._find_nodes(root, "function_definition"):
            name_node = node.child_by_field_name("declarator")
            if name_node:
                # 递归查找 identifier
                name = self._get_c_function_name(name_node)
                if name:
                    params = self._get_c_params(node)
                    line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    parsed.functions.append(FunctionInfo(name, line, end_line, params))

        # 查找函数调用
        for node in self._find_nodes(root, "call_expression"):
            callee = self._get_c_call_name(node)
            if callee:
                caller = self._get_current_function(node, root)
                line = node.start_point[0] + 1
                parsed.calls.append(CallInfo(caller, callee, line))

        # 查找 #include
        for node in self._find_nodes(root, "preproc_include"):
            try:
                path_node = node.child_by_field_name("path")
                if path_node:
                    parsed.imports.append(path_node.text.decode("utf-8"))
            except Exception:
                pass

    def _extract_cpp_info(self, parsed: ParsedCode) -> None:
        """提取 C++ 代码信息（复用 C 的逻辑）"""
        self._extract_c_info(parsed)

    def _get_c_function_name(self, node: Any) -> str | None:
        """递归获取 C 函数名"""
        if node.type == "identifier":
            try:
                return node.text.decode("utf-8")
            except Exception:
                return None
        for child in node.children:
            name = self._get_c_function_name(child)
            if name:
                return name
        return None

    def _get_c_params(self, node: Any) -> list[str]:
        """获取 C 函数参数"""
        params = []
        for child in node.children:
            if child.type == "parameter_list":
                for param in child.children:
                    if param.type == "parameter_declaration":
                        # 尝试获取参数名
                        for sub in param.children:
                            if sub.type == "identifier":
                                try:
                                    params.append(sub.text.decode("utf-8"))
                                except Exception:
                                    pass
        return params

    def _get_c_call_name(self, node: Any) -> str | None:
        """获取 C 函数调用名"""
        func = node.child_by_field_name("function")
        if func:
            if func.type == "identifier":
                try:
                    return func.text.decode("utf-8")
                except Exception:
                    pass
            elif func.type == "field_expression":
                # 处理 obj.method 形式
                try:
                    return func.text.decode("utf-8")
                except Exception:
                    pass
        return None

    def _find_nodes(self, root: Any, node_type: str) -> Iterator[Any]:
        """递归查找指定类型的节点"""
        if root.type == node_type:
            yield root
        for child in root.children:
            yield from self._find_nodes(child, node_type)

    def _get_func_name(self, node: Any) -> str | None:
        """获取函数名"""
        # 尝试不同的节点类型
        for child in node.children:
            if child.type in ("identifier", "attribute"):
                try:
                    return child.text.decode("utf-8")
                except Exception:
                    pass
        return None

    def _get_func_params(self, node: Any, lang: str) -> list[str]:
        """获取函数参数列表"""
        params = []
        for child in node.children:
            if child.type == "parameters":
                for param in child.children:
                    if param.type == "identifier":
                        try:
                            params.append(param.text.decode("utf-8"))
                        except Exception:
                            pass
        return params

    def _get_call_name(self, node: Any) -> str | None:
        """获取函数调用名"""
        for child in node.children:
            if child.type in ("identifier", "attribute"):
                try:
                    return child.text.decode("utf-8")
                except Exception:
                    pass
        return None

    def _get_java_method_name(self, node: Any) -> str | None:
        """
        获取 Java 方法调用名

        Java method_invocation 节点结构:
          object.method(args)
          ├── object (identifier / field_access)
          ├── . (separator)
          ├── method (identifier)  <-- 我们需要这个
          └── (arguments)

        或者直接调用:
          method(args)
          ├── method (identifier)
          └── (arguments)
        """
        # 方法1: 使用 Tree-sitter 的 name 字段
        name_node = node.child_by_field_name("name")
        if name_node:
            try:
                return name_node.text.decode("utf-8")
            except Exception:
                pass

        # 方法2: 查找 identifier 类型的子节点（取最后一个，即方法名）
        last_identifier = None
        for child in node.children:
            if child.type == "identifier":
                try:
                    last_identifier = child.text.decode("utf-8")
                except Exception:
                    pass

        return last_identifier

    def _get_js_call_name(self, node: Any) -> str | None:
        """获取 JavaScript 函数调用名"""
        func = node.child_by_field_name("function")
        if func:
            if func.type == "identifier":
                try:
                    return func.text.decode("utf-8")
                except Exception:
                    pass
            elif func.type == "member_expression":
                # 处理 obj.method() 形式
                try:
                    obj = func.child_by_field_name("object")
                    prop = func.child_by_field_name("property")
                    if obj and prop:
                        return f"{obj.text.decode('utf-8')}.{prop.text.decode('utf-8')}"
                except Exception:
                    pass
        return None

    def _get_php_call_name(self, node: Any) -> str | None:
        """获取 PHP 方法调用名"""
        for child in node.children:
            if child.type in ("member_name", "name"):
                try:
                    return child.text.decode("utf-8")
                except Exception:
                    pass
        return None

    def _get_current_function(self, node: Any, root: Any) -> str | None:
        """获取当前节点所属的函数名"""
        # 向上查找函数定义
        parent = node.parent
        while parent:
            if parent.type in ("function_definition", "function_declaration",
                               "method_declaration", "function_declaration"):
                return self._get_func_name(parent)
            parent = parent.parent
        return None

    def _get_import_names(self, node: Any) -> list[str]:
        """获取 Python import 名称"""
        names = []
        for child in node.children:
            try:
                text = child.text.decode("utf-8")
                if text and not text.startswith("import") and text.strip():
                    names.append(text.strip())
            except Exception:
                pass
        return names

    def _get_js_import_names(self, node: Any) -> list[str]:
        """获取 JavaScript import 名称"""
        names = []
        for child in node.children:
            try:
                text = child.text.decode("utf-8")
                if text and text.strip():
                    names.append(text.strip())
            except Exception:
                pass
        return names

    def _get_java_params(self, node: Any) -> list[str]:
        """获取 Java 方法参数"""
        params = []
        for child in node.children:
            if child.type == "formal_parameters":
                for param in child.children:
                    if param.type == "formal_parameter":
                        name_node = param.child_by_field_name("name")
                        if name_node:
                            try:
                                params.append(name_node.text.decode("utf-8"))
                            except Exception:
                                pass
        return params

    def _get_go_params(self, node: Any) -> list[str]:
        """获取 Go 函数参数"""
        params = []
        for child in node.children:
            if child.type == "parameter_list":
                for param in child.children:
                    try:
                        text = param.text.decode("utf-8")
                        if text.strip():
                            params.append(text.strip())
                    except Exception:
                        pass
        return params

    def _get_php_params(self, node: Any) -> list[str]:
        """获取 PHP 函数参数"""
        params = []
        for child in node.children:
            if child.type == "parameters":
                for param in child.children:
                    try:
                        text = param.text.decode("utf-8")
                        if text.strip():
                            params.append(text.strip())
                    except Exception:
                        pass
        return params

    def _get_decorators(self, node: Any) -> list[str]:
        """获取装饰器列表"""
        decos = []
        for child in node.children:
            if child.type == "decorator":
                try:
                    text = child.text.decode("utf-8").strip()
                    if text.startswith("@"):
                        decos.append(text)
                except Exception:
                    pass
        return decos

    def _get_decorated_func(self, node: Any) -> Any:
        """获取被装饰器修饰的函数节点"""
        for child in node.children:
            if child.type in ("function_definition", "function_declaration"):
                return child
        return None

    def _extract_route_path(self, deco: str) -> str | None:
        """从装饰器中提取路由路径"""
        # 匹配 @app.route('/path') 或 @route("/path")
        match = re.search(r"[\"\']([^\"\']+)[\"\']", deco)
        if match:
            return match.group(1)
        return None


# 全局单例实例
_global_parser: TreeSitterParser | None = None


def get_parser() -> TreeSitterParser:
    """获取全局 Tree-sitter 解析器实例"""
    global _global_parser
    if _global_parser is None:
        _global_parser = TreeSitterParser()
    return _global_parser


def parse_code(
    source: str,
    language: LanguageType | str,
    file_path: str = "<string>"
) -> ParsedCode | None:
    """
    便捷函数：解析代码

    Args:
        source: 源代码
        language: 语言类型（可以是字符串或枚举）
        file_path: 文件路径

    Returns:
        ParsedCode 对象
    """
    if isinstance(language, str):
        language = LanguageType(language)

    parser = get_parser()
    return parser.parse(source, language, file_path)


def parse_file(file_path: str) -> ParsedCode | None:
    """
    便捷函数：解析文件

    Args:
        file_path: 文件路径

    Returns:
        ParsedCode 对象
    """
    parser = get_parser()
    return parser.parse_file(file_path)
