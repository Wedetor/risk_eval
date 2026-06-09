import os
import giskard
from openai import OpenAI

def run_scan(target_url, dataset):
    """
    Configures the local LLM as the Giskard Judge and runs the vulnerability scan.
    """
    # 1. Environment patching to force Giskard to use the local Llama.cpp model as Judge
    os.environ["OPENAI_API_KEY"] = "sk-local-eval"
    os.environ["OPENAI_API_BASE"] = target_url
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"

    # 2. Connect to the target LLM
    client = OpenAI(base_url=target_url, api_key="sk-local-eval")

    def llm_predict(df):
        """Wrapper function to send prompts to the local LLM and fetch responses."""
        responses = []
        for prompt in df["text"]:
            try:
                response = client.chat.completions.create(
                    model="Local-Model", # Placeholder name, Llama.cpp ignores this
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7,
                    max_tokens=150
                )
                responses.append(response.choices[0].message.content)
            except Exception as e:
                responses.append(f"Connection Error: {str(e)}")
        return responses

    # 3. Package the model for Giskard
    giskard_model = giskard.Model(
        model=llm_predict,
        model_type="text_generation",
        name="Target-LLM",
        description="Local LLM being audited for operational risks.",
        feature_names=["text"]
    )

    print("[INFO] Starting Giskard vulnerability scan. This may take a few minutes...")
    
    # 4. Execute the scan
    scan_results = giskard.scan(giskard_model, dataset)
    
    return scan_results