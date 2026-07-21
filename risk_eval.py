import argparse
import time
from dotenv import load_dotenv

from core.config_manager import load_config, save_config
from core.dataset_manager import prepare_data
from core.evaluator import run_scan
from core.metrics import calculate_metrics

def parse_arguments():
    saved_config = load_config()
    parser = argparse.ArgumentParser(description="RiskEval: LLM risk assessment tool.")

    parser.add_argument("-age", "--age", choices=['all', '-18', '18-29', '30-44', '45-65', '+65'], help="Target user age range.")
    parser.add_argument("-ind", "--industry", choices=['general', 'manufacturing', 'electricity', 'transportation', 'information', 'finance', 'professional', 'public_admin', 'education', 'health'], help="Industry sector.")
    parser.add_argument("-mode", "--mode", choices=['simple', 'advanced', 'complete'], default='complete', help="Scan mode: simple, advanced, or complete.")
    parser.add_argument("--target-url", help="Local Llama.cpp API URL")
    
    args = parser.parse_args()

    final_config = {
        "age": args.age or saved_config.get("age", "all"),
        "industry": args.industry or saved_config.get("industry", "general"),
        "mode": args.mode or saved_config.get("mode", "complete"),
        "target_url": args.target_url or saved_config.get("target_url", "http://localhost:5001/v1"),
    }
    save_config(final_config)
    return final_config

def main():
    start_time = time.time()
    load_dotenv()
    config = parse_arguments()
    
    print("\n" + "="*50)
    print(f"[+] Running RiskEval | Mode: {config['mode'].upper()}")
    print("="*50)
    
    # 1. Load or create test datasets
    data_simple, data_advanced = prepare_data()
    
    # 2. Run scan based on selected mode
    res_simple, res_advanced = run_scan(
        config['target_url'], 
        data_simple, 
        data_advanced, 
        mode=config['mode']
    )
    
    # 3. Calculate metrics and save reports
    calculate_metrics(res_simple, res_advanced, config['age'], config['industry'], mode=config['mode'])

    # Time elapsed
    elapsed_time = time.time() - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    print("\n" + "="*50)
    print(f"[i] Total execution time: {int(minutes)}m {seconds:.2f}s")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()