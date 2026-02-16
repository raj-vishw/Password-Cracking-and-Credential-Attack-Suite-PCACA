import os
from .mutatios import MutationEngine
from .pattern_engine import PatternEngine

OUTPUT_PATH = "wordlists/dictionary.txt"


class DictionaryGenerator:
    def __init__(self, name=None, dob=None, custom_words=None):
        self.name = name
        self.dob = dob
        self.custom_words = custom_words or []

    def generate(self):
        os.makedirs("wordlists", exist_ok=True)

        base_patterns = set(self.custom_words)

        pattern_engine = PatternEngine(self.name, self.dob)
        base_patterns.update(pattern_engine.generate())

        mutation_engine = MutationEngine(base_patterns)
        final_words = mutation_engine.generate()

        with open(OUTPUT_PATH, "w") as f:
            for word in sorted(final_words):
                f.write(word + "\n")

        return {
            "output_file": OUTPUT_PATH,
            "total_generated": len(final_words)
        }