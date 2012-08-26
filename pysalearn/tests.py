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
        self.assertEqual(report.reporter_id, "1T5gDL-0005Sc-4O")
        self.assertEqual(report.reported_id, "1T4ezk-0006c6-Hp")

if __name__ == '__main__':
    unittest.main()
