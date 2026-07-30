import argparse
import time
from dotenv import load_dotenv

from core.config_manager import load_config, save_config
from core.dataset_manager import prepare_data
from core.evaluator import run_scan
from core.metrics import calculate_metrics, count_giskard_hits, get_category_totals

def parse_arguments():
    saved_config = load_config()
    parser = argparse.ArgumentParser(description="RiskEval: LLM risk assessment tool.")

    parser.add_argument("-age", "--age", choices=['all', '-18', '18-29', '30-44', '45-65', '+65'], help="Target user age range.")
    parser.add_argument("-ind", "--industry", choices=['manufacturing', 'electricity', 'transportation', 'information', 'finance', 'professional', 'public_admin', 'education', 'health'], help="Industry sector.")
    parser.add_argument("--target-url", help="Local Llama.cpp API URL")
    
    args = parser.parse_args()
    final_config = {
        "age": args.age or saved_config.get("age", "all"),
        "industry": args.industry or saved_config.get("industry", "education"),
        "target_url": args.target_url or saved_config.get("target_url", "http://localhost:5001/v1"),
    }
    save_config(final_config)
    return final_config

def main():
    start_time = time.time()
    load_dotenv()
    config = parse_arguments()
    
    print("\n" + "="*50)
    print(f"[+] Running RiskEval | Unified 10-Pass Evaluation")
    print("="*50)
    
    data_simple, data_advanced = prepare_data()
    
    # Setup for 10 passes
    NUM_PASSES = 10
    keys = ["conf", "avai", "misi", "inap", "tsup"]
    acc_simple = {k: 0 for k in keys}
    acc_adv = {k: 0 for k in keys}

    print(f"[i] Starting rigorous evaluation: {NUM_PASSES} independent passes...")

    for i in range(NUM_PASSES):
        print(f"\n--- Pass {i+1} of {NUM_PASSES} ---")
        
        # Run unified scan
        res_simple, res_advanced = run_scan(
            config['target_url'], data_simple, data_advanced
        )
        
        # Accumulate simple hits
        if res_simple:
            for k in keys: acc_simple[k] += res_simple.get(k, 0)
        
        # Accumulate advanced hits
        if res_advanced:
            adv_hits_dict = count_giskard_hits(res_advanced)
            for k in keys: acc_adv[k] += adv_hits_dict.get(k, 0)

    # Average hits across all passes
    avg_simple = {k: v / NUM_PASSES for k, v in acc_simple.items()}
    avg_adv = {k: v / NUM_PASSES for k, v in acc_adv.items()}
    
    print("\n[+] Calculation of averages complete. Generating unified metrics...")

    # Load T totals unconditionally
    tot_simple = get_category_totals("data/simple_induction.csv", avg_simple)
    tot_adv = get_category_totals("data/advanced_induction.csv", avg_adv)

    # Execute final math
    calculate_metrics(
        simple_hits=avg_simple, 
        adv_hits=avg_adv, 
        totals_simple=tot_simple, 
        totals_adv=tot_adv, 
        age_group=config['age'], 
        industry=config['industry']
    )

    elapsed = time.time() - start_time
    m, s = divmod(elapsed, 60)
    print("\n" + "="*50)
    print(f"[i] Total execution time: {int(m)}m {s:.2f}s")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()