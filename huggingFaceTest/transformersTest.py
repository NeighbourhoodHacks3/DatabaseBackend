from transformers import AutoModelForCausalLM

model = AutoModelForCausalLM.from_pretrained("model_name")

def generate_text(input_text):
    generated_text = model.generate(input_text, max_length=100)
    return generated_text

print(generate_text("What's up? I'm looking for help, I want to start an art business idk what to do.", max_length=50, do_sample=False))
