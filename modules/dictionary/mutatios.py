class MutationEngine:
    LEET_MAP = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7']
    }

    SYMBOLS = ['!', '@', '#', '$', '%', '^', '&', '*']

    def __init__(self, base_words):
        self.base_words = base_words

    def apply_case_variations(self, word):
        return {
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase()
        }

    def apply_leet(self, word):
        variations = {word}
        for i, char in enumerate(word):
            if char.lower() in self.LEET_MAP:
                for replacement in self.LEET_MAP[char.lower()]:
                    mutated = word[:i] + replacement + word[i + 1:]
                    variations.add(mutated)
        return variations

    def append_numbers(self, word, max_range=100):
        return {f"{word}{num}" for num in range(max_range)}

    def append_symbols(self, word):
        return {f"{word}{symbol}" for symbol in self.SYMBOLS}

    def generate(self):
        results = set()

        for word in self.base_words:
            case_variations = self.apply_case_variations(word)

            for variant in case_variations:
                results.add(variant)

                leet_variants = self.apply_leet(variant)
                results.update(leet_variants)

                for lv in leet_variants:
                    results.update(self.append_numbers(lv))
                    results.update(self.append_symbols(lv))

        return results