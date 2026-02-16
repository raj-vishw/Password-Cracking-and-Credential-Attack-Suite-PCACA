class TimeEstimator:
    def __init__(self, charset_size, max_length, attempts_per_second = 1_000_000):
        self.charset_size = charset_size
        self.max_length = max_length
        self.attempts_per_second = attempts_per_second
    
    def total_combinations(self):
        total = 0
        for i in range(1, self.max_length+1):
            total += self.charset_size ** i
        return total
    
    def estimated_time(self):
        total = self.total_combinations()
        return round(total / self.attempts_per_second,2)