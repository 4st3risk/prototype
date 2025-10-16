import logging
import sys

targets = logging.StreamHandler(sys.stdout), logging.FileHandler('test.log')

logging.basicConfig(format='%(message)s', level=logging.INFO, handlers=targets)

logging.info("Test log system.")
logging.info("\n")
logging.info("Second message")


