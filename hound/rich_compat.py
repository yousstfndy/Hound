from __future__ import annotations

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ModuleNotFoundError:

    class Console:
        def print(self, *args: object, **_: object) -> None:
            print(*[strip_markup(str(arg)) for arg in args])

    class Panel:
        def __init__(self, renderable: object, title: str | None = None, expand: bool = False) -> None:
            self.renderable = renderable
            self.title = title

        def __str__(self) -> str:
            title = f"{self.title}\n" if self.title else ""
            return title + str(self.renderable)

    class Table:
        def __init__(self, title: str | None = None) -> None:
            self.title = title
            self.columns: list[str] = []
            self.rows: list[tuple[str, ...]] = []

        @classmethod
        def grid(cls, padding: tuple[int, int] = (0, 1)) -> "Table":
            return cls()

        def add_column(self, name: str = "", **_: object) -> None:
            self.columns.append(name)

        def add_row(self, *values: object) -> None:
            self.rows.append(tuple(strip_markup(str(value)) for value in values))

        def __str__(self) -> str:
            lines = [self.title] if self.title else []
            if self.columns and any(self.columns):
                lines.append(" | ".join(self.columns))
            lines.extend(" | ".join(row) for row in self.rows)
            return "\n".join(lines)


def strip_markup(value: str) -> str:
    for token in ["[red]", "[/red]", "[yellow]", "[/yellow]", "[green]", "[/green]", "[blue]", "[/blue]"]:
        value = value.replace(token, "")
    return value.replace("✓", "OK").replace("✗", "X").replace("—", "-")
