import subprocess
import sys

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def run_script(name: str, args: list[str] = []) -> bool:
    print(f"\n{Colors.BOLD}{Colors.CYAN}[RUNNING] {name}{Colors.END}")
    cmd = [sys.executable, name] + args
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print(f"{Colors.GREEN}[PASS] {name} succeeded.{Colors.END}")
        return True
    else:
        print(f"{Colors.RED}[FAIL] {name} failed with exit code {result.returncode}.{Colors.END}")
        return False

def main():
    print(f"{Colors.BOLD}{Colors.YELLOW}==================================================")
    print("         CHORUS SUITE TERMINAL RUNNER & TESTER     ")
    print(f"=================================================={Colors.END}")

    success = True
    
    # 1. Math Tests
    success &= run_script("test_math.py")
    
    # 2. Protocol Integration & Unit Tests
    success &= run_script("test_protocol.py")
    
    # 3. Protocol CLI Demo
    success &= run_script("demo_cli.py")

    print(f"\n{Colors.BOLD}{Colors.YELLOW}==================================================")
    if success:
        print(f"  {Colors.GREEN}ALL CHORUS PROTOCOL TESTS & DEMONSTRATION PASSED!{Colors.END}")
    else:
        print(f"  {Colors.RED}SOME CHORUS PROTOCOL TESTS FAILED.{Colors.END}")
    print(f"=================================================={Colors.END}")
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
