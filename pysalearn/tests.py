import unittest
import pysalearn



class TestNotMultipartException(unittest.TestCase):

    def setUp(self):
        self.config = pysalearn.loadConfig()
        self.raw_message = eval(open("examples/not_multipart.rawemail").readline().strip())

    def test_id_extraction(self):
        with self.assertRaises(pysalearn.EmailException):
            pysalearn.extract_id_from_msg(self.raw_message, 
                                      self.config.get('AUTH REPORTERS', 'spamReportHeaderKey'))


class TestValidExtraction(unittest.TestCase):
    def setUp(self):
        self.reportHeader = "X-MyServer-MailScanner-SpamCheck"
        self.raw_message = eval(open("examples/valid.rawemail").readline().strip())

    def test_id_extraction(self):
        report = pysalearn.extract_id_from_msg(self.raw_message, self.reportHeader)
        print report.reporter_id

if __name__ == '__main__':
    unittest.main()