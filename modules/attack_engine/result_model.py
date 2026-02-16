class AttackResult:
    """
    Unified attack result structure.
    Used by brute-force and dictionary engines.
    """

    def __init__(self,
                 attack_type,
                 success,
                 password,
                 attempts,
                 duration,
                 algorithm,
                 metadata=None):

        self.attack_type = attack_type
        self.success = success
        self.password = password
        self.attempts = attempts
        self.duration = duration
        self.algorithm = algorithm
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "attack_type": self.attack_type,
            "success": self.success,
            "password": self.password,
            "attempts": self.attempts,
            "duration_seconds": round(self.duration, 4),
            "algorithm": self.algorithm,
            "metadata": self.metadata
        }
