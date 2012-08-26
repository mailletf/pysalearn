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
        self.raw_messages = [("valid", ("1T5gDL-0005Sc-4O", "1T4ezk-0006c6-Hp")),
                   ("valid_fromhorde", ("1T5hrU-00066C-Td", "1T4ezk-0006c6-Hp"))]
        
    def test_id_extraction(self):
        for fn, goodIds in self.raw_messages:
            raw_message = eval(open("examples/%s.rawemail" % fn).readline().strip())
            report = pysalearn.extract_id_from_msg(raw_message, self.reportHeader)
            self.assertEqual(report.reporter_id, goodIds[0])
            self.assertEqual(report.reported_id, goodIds[1])


if __name__ == '__main__':
    unittest.main()
