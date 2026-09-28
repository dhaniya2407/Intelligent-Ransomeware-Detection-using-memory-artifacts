from forensic_engine.volatility_engine import analyze_memory
import os


memory_path = r"C:\Users\dhani\Downloads\memory.raw"

output_folder = "analysis_results"

os.makedirs(output_folder, exist_ok=True)


print("======================================")
print("FORENSIRANSOM AI")
print("MEMORY FORENSIC ANALYSIS")
print("======================================")

print("\nStarting Volatility analysis...\n")


results = analyze_memory(memory_path)


for name, result in results.items():

    print("\n==============================")
    print(name)
    print("==============================")

    if result["success"]:

        output = result["raw_output"]

        print(output[:2000])

        output_file = os.path.join(
            output_folder,
            f"{name}.txt"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            file.write(output)

        print(f"\nSaved to: {output_file}")

    else:

        print("ERROR:")
        print(result["error"])


print("\n======================================")
print("ANALYSIS COMPLETED")
print("======================================")