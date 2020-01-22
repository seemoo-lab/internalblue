

from .all_traces_test import generate_test_suite

def load_tests(loader, standard_tests, n):
    return generate_test_suite()