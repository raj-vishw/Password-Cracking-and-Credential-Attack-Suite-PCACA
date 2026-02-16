from .dictionary_attack import DictionaryAttackEngine
from .brute_force import BruteForceEngine


class AttackController:
    """
    Orchestrates attack strategy.
    Supports:
        - dictionary only
        - brute force only
        - hybrid (dictionary → brute-force fallback)
    """

    def __init__(self, hash_value, algorithm="md5"):
        self.hash_value = hash_value
        self.algorithm = algorithm

    def dictionary_attack(self, word_source):
        engine = DictionaryAttackEngine(
            hash_value=self.hash_value,
            algorithm=self.algorithm,
            word_source=word_source
        )
        return engine.run()

    def brute_force_attack(self,
                           charset="lower",
                           min_length=1,
                           max_length=6):

        engine = BruteForceEngine(
            hash_value=self.hash_value,
            algorithm=self.algorithm,
            charset=charset,
            min_length=min_length,
            max_length=max_length
        )
        return engine.run()

    def hybrid_attack(self,
                      word_source,
                      charset="lower",
                      min_length=1,
                      max_length=6):

        # Step 1: Dictionary
        dict_result = self.dictionary_attack(word_source)

        if dict_result["success"]:
            dict_result["metadata"]["strategy"] = "dictionary_only"
            return dict_result

        # Step 2: Brute-force fallback
        brute_result = self.brute_force_attack(
            charset=charset,
            min_length=min_length,
            max_length=max_length
        )

        brute_result["metadata"]["strategy"] = "dictionary_then_bruteforce"
        return brute_result
