"""一键测试入口：python run_tests.py [测试模块...]

不带参数时运行全部测试（含十万连接规模测试，约 1 分钟）。
例如只跑快速用例：python run_tests.py tests.test_engine tests.test_cidr
"""

import sys
import unittest

if __name__ == "__main__":
    if len(sys.argv) > 1:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(sys.argv[1:])
    else:
        loader = unittest.TestLoader()
        suite = loader.discover(start_dir="tests", top_level_dir=".",
                                pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
