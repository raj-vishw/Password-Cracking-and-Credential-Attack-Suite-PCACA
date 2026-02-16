import argparse
import sys
import hashlib

from modules.dictionary.generator import DictionaryGenerator
from modules.dictionary.pattern_engine import PatternEngine

from modules.hash_extraction.linux_shadow import LinuxShadowExtractor
from modules.hash_extraction.windows_sam_extractor import WindowsSAMExtractor

from modules.attack_engine.attack_controller import AttackController

from modules.strength_analysis.analyzer import PasswordStrengthAnalyzer

from modules.reporting.report_builder import AuditReportBuilder

def handle_generate_dict(args):
    generator = DictionaryGenerator(
        name=args.name,
        dob=args.dob,
        custom_words=args.custom
    )

    result = generator.generate()

    print("\n[+] Dictionary Generated")
    print(f"Output File: {result['output_file']}")
    print(f"Total Words: {result['total_generated']}")


def handle_extract_linux(args):
    extractor = LinuxShadowExtractor(args.shadow)

    try:
        results = extractor.parse_shadow()
        print(f"\n[+] Extracted {len(results)} hashes")

        for entry in results:
            print(f"{entry['username']} -> {entry['algorithm']}")

    except Exception as e:
        print(f"[!] Error: {e}")


def handle_extract_windows(args):
    extractor = WindowsSAMExtractor(args.sam, args.system)

    try:
        results = extractor.extract()
        print(f"\n[+] Extracted {len(results)} NTLM hashes")

        for entry in results:
            print(f"{entry['username']} -> {entry['ntlm_hash']}")

    except Exception as e:
        print(f"[!] Error: {e}")


def handle_attack(args):
    controller = AttackController(args.hash, algorithm=args.algorithm)

    if args.mode == "dictionary":
        if not args.wordlist:
            print("[!] --wordlist required for dictionary mode")
            sys.exit(1)

        result = controller.dictionary_attack(args.wordlist)

    elif args.mode == "brute":
        result = controller.brute_force_attack(
            charset=args.charset,
            min_length=args.min,
            max_length=args.max
        )

    elif args.mode == "hybrid":
        if not args.wordlist:
            print("[!] --wordlist required for hybrid mode")
            sys.exit(1)

        result = controller.hybrid_attack(
            word_source=args.wordlist,
            charset=args.charset,
            min_length=args.min,
            max_length=args.max
        )

    else:
        print("[!] Invalid attack mode")
        sys.exit(1)

    print("\n=== ATTACK RESULT ===")
    for k, v in result.items():
        print(f"{k}: {v}")


def handle_analyze(args):
    pattern_engine = PatternEngine(
        name=args.name,
        dob=args.dob
    )

    analyzer = PasswordStrengthAnalyzer(pattern_engine)
    result = analyzer.analyze(args.password)

    print("\n=== PASSWORD ANALYSIS ===")
    for k, v in result.items():
        print(f"{k}: {v}")


def main():

    parser = argparse.ArgumentParser(
        description="Password Cracking & Credential Attack Suite"
    )

    subparsers = parser.add_subparsers(dest="command")

    dict_parser = subparsers.add_parser("generate-dict")
    dict_parser.add_argument("--name", help="Target name")
    dict_parser.add_argument("--dob", help="Date of birth")
    dict_parser.add_argument("--custom", nargs="*", help="Custom base words")

    linux_parser = subparsers.add_parser("extract-linux")
    linux_parser.add_argument("--shadow", default="/etc/shadow",
                              help="Path to shadow file")

    win_parser = subparsers.add_parser("extract-windows")
    win_parser.add_argument("--sam", required=True,
                            help="Path to SAM hive")
    win_parser.add_argument("--system", required=True,
                            help="Path to SYSTEM hive")

    attack_parser = subparsers.add_parser("attack")
    attack_parser.add_argument("--hash", required=True,
                               help="Target hash")
    attack_parser.add_argument("--algorithm", default="md5",
                               help="Hash algorithm")
    attack_parser.add_argument("--mode",
                               choices=["dictionary", "brute", "hybrid"],
                               required=True)
    attack_parser.add_argument("--wordlist",
                               help="Wordlist file (for dictionary/hybrid)")
    attack_parser.add_argument("--charset", default="lower",
                               help="Charset for brute-force")
    attack_parser.add_argument("--min", type=int, default=1,
                               help="Minimum length")
    attack_parser.add_argument("--max", type=int, default=6,
                               help="Maximum length")

    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("--password", required=True)
    analyze_parser.add_argument("--name")
    analyze_parser.add_argument("--dob")

    args = parser.parse_args()

    if args.command == "generate-dict":
        handle_generate_dict(args)

    elif args.command == "extract-linux":
        handle_extract_linux(args)

    elif args.command == "extract-windows":
        handle_extract_windows(args)

    elif args.command == "attack":
        handle_attack(args)

    elif args.command == "analyze":
        handle_analyze(args)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
