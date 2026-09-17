import unittest
from guard7702.detector import inspect,score

class DetectorTests(unittest.TestCase):
    def test_explanation_and_ablation(self):
        e={'universal':True,'code_mismatch':True}
        self.assertEqual(score(e),(6,['universal','code_mismatch']))
        self.assertEqual(score(e,('code_mismatch',))[0],2)
        self.assertTrue(inspect(e)['alert'])
    def test_label_does_not_affect_prediction(self):
        self.assertEqual(inspect({'label':1}),inspect({'label':0}))
