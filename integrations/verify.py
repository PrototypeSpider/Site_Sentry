"""Run an opt-in Gemini/Grok live connectivity and schema check."""

import argparse
import json
from dotenv import load_dotenv

from .explainer import verify_provider


def main():
    # Direct `python -m` use does not otherwise guarantee that .env is loaded.
    # Preserve process-level settings if present.
    load_dotenv(override=False)
    parser=argparse.ArgumentParser(description="Verify an explicitly configured SiteSentry explanation provider.")
    parser.add_argument("provider",choices=["gemini","grok"],nargs="?")
    args=parser.parse_args()
    result=verify_provider(args.provider)
    # Never print API keys or full request environment.
    print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result["status"]=="ok" else 1)


if __name__=="__main__": main()
