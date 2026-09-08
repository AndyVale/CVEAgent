"""Enforce package boundaries without importing providers or constructing services."""
from pathlib import Path
import ast


SOURCE = Path(__file__).parents[2] / 'src' / 'cve_agent'
ALLOWED = {
    'core': {'core'},
    'runtime': {'runtime', 'core'},
    'investigation': {'investigation', 'runtime', 'core'},
    'classification': {'classification', 'runtime', 'core'},
    'integrations': {'integrations', 'runtime', 'core'},
    'persistence': {'persistence', 'core'},
    'cache': {'cache', 'integrations', 'runtime', 'core'},
    'application': {'application', 'classification', 'investigation', 'persistence', 'cache', 'integrations', 'runtime', 'core'},
    'cli': {'cli', 'application', 'classification', 'persistence', 'runtime', 'core'},
    'gui': {'gui', 'application', 'classification', 'persistence', 'cache', 'runtime', 'core'},
}


def import_graph():
    modules = {}
    for path in SOURCE.rglob('*.py'):
        parts = path.relative_to(SOURCE.parent).with_suffix('').parts
        module = '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)
        modules[module] = path
    graph = {module: set() for module in modules}
    for module, path in modules.items():
        package = module if path.name == '__init__.py' else module.rsplit('.', 1)[0]
        for node in ast.walk(ast.parse(path.read_text())):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ''
                if node.level:
                    parent = package.split('.')[:len(package.split('.')) - node.level + 1]
                    base = '.'.join([*parent, *([base] if base else [])])
                targets = [base, *(f'{base}.{alias.name}' for alias in node.names)]
            for target in targets:
                if target in modules and target != module:
                    graph[module].add(target)
                elif target == module:
                    graph[module].add(target)
                if target.startswith('cve_agent.'):
                    parts = target.split('.')
                    for count in range(1, len(parts)):
                        parent = '.'.join(parts[:count])
                        if parent in modules and parent != module:
                            graph[module].add(parent)
    return graph


def test_dependency_boundaries():
    assert SOURCE.is_dir()
    assert set(ALLOWED) <= {path.name for path in SOURCE.iterdir() if path.is_dir()}
    violations = []
    for module, dependencies in import_graph().items():
        parts = module.split('.')
        if len(parts) < 2 or parts[1] == '__main__':
            continue
        layer = parts[1]
        assert layer in ALLOWED, f'Unexpected top-level module: {module}'
        for dependency in dependencies:
            target = dependency.split('.')[1:2]
            if target and target[0] not in ALLOWED[layer]:
                violations.append(f'{module} -> {dependency}')
    assert not violations, '\n'.join(sorted(violations))


def test_import_graph_has_no_cycles():
    graph = import_graph()
    visited = set()

    def visit(module, stack):
        assert module not in stack, ' -> '.join([*stack, module])
        if module in visited:
            return
        for dependency in sorted(graph[module]):
            visit(dependency, [*stack, module])
        visited.add(module)

    for module in sorted(graph):
        visit(module, [])
