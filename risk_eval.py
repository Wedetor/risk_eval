import argparse
from dotenv import load_dotenv

# Import modules from core package
from core.config_manager import load_config, save_config
from core.dataset_manager import prepare_data
from core.evaluator import run_scan
from core.metrics import calculate_metrics

def parse_arguments():
    saved_config = load_config()
    parser = argparse.ArgumentParser(description="RiskEval: Multidimensional audit tool for LLMs.")

    parser.add_argument(
        "-age", "--age", 
        choices=['all', '-18', '18-29', '30-44', '45-65', '+65'], 
        help="Target user age range."
    )
    
    # Added all industries from the theoretical framework
    parser.add_argument(
        "-ind", "--industry", 
        choices=[
            'general', 'manufacturing', 'electricity', 'transportation', 
            'information', 'finance', 'professional', 'public_admin', 
            'education', 'health'
        ], 
        help="Industrial sector where the chatbot will operate."
    )
    
    parser.add_argument("--target-url", help="URL of the local Llama.cpp API (e.g., http://localhost:5001/v1)")
    parser.add_argument("--dataset", help="Path to a frozen .csv file to ensure reproducibility.")

    args = parser.parse_args()

    final_config = {
        "age": args.age or saved_config.get("age", "all"),
        "industry": args.industry or saved_config.get("industry", "general"),
        "target_url": args.target_url or saved_config.get("target_url", "http://localhost:5001/v1"),
        "dataset": args.dataset or saved_config.get("dataset", None)
    }

    save_config(final_config)
    return final_config

def main():
    # 1. Load API Keys silently from .env
    load_dotenv()
    
    # 2. Parse configuration
    config = parse_arguments()
    
    print("\n" + "="*50)
    print("[+] Starting RiskEval")
    print("="*50)
    print(f"    - Target Age : {config['age']}")
    print(f"    - Industry   : {config['industry']}")
    print(f"    - Target URL : {config['target_url']}")
    print(f"    - Dataset    : {config['dataset'] if config['dataset'] else 'Active Generation Mode'}")
    print("="*50 + "\n")

    # 3. Pipeline Execution
    # Step A: Load or generate dataset
    dataset = prepare_data(config['dataset'])
    
    # Step B: Run Giskard Scan
    scan_results = run_scan(config['target_url'], dataset)
    
    # Step C: Calculate metrics based on the theoretical model
    calculate_metrics(scan_results, config['age'], config['industry'])

    # Step D: Optional - Save raw HTML report for human review
    scan_results.to_html("giskard_raw_report.html")
    print("[+] Raw HTML report saved to 'giskard_raw_report.html'")

if __name__ == "__main__":
    main()