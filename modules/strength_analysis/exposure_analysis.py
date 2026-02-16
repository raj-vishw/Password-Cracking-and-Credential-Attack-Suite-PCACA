class ExposureAnalyzer:
    def __init__(self, pattern_engine=None):
        self.pattern_engine = pattern_engine

    def check_dictionary_exposure(self, password):

        if not self.pattern_engine:
            return False
        generated = self.pattern_engine.generate()

        return password in generated