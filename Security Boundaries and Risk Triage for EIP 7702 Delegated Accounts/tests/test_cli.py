import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from guard7702.cli import main
from guard7702.benchmark import metrics, run


class CommandTests(unittest.TestCase):
    def test_demo_replay(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['demo']), 0)
        for result in json.loads(output.getvalue())['chains'].values():
            self.assertEqual(result['first_submission'], 'accepted')
            self.assertEqual(result['same_chain_replay'], 'nonce')

    def test_invalid_observation_is_not_silently_benign(self):
        for data in ['{}', '{"universal":"false"}', '[]', '{invalid']:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/'events.jsonl'
                path.write_text(data, encoding='utf-8')
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    self.assertEqual(main(['inspect', str(path)]), 2)
                self.assertIn('line 1:', error.getvalue())

    def test_inspect_threshold(self):
        path = Path(__file__).resolve().parents[1]/'examples/observations.jsonl'
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['inspect', str(path), '--threshold', '5']), 0)
        self.assertEqual([json.loads(s)['alert'] for s in output.getvalue().splitlines()], [False, False])

    def test_metrics_known_confusion_matrix(self):
        result = metrics([True, True, False, False], [True, False, True, False])
        self.assertEqual([result[k] for k in ('tp', 'fp', 'fn', 'tn')], [1, 1, 1, 1])
        self.assertEqual(result['f1'], .5)

    def test_benchmark_is_reproducible(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder)/'a', Path(folder)/'b'
            result = run(first, seeds=1, events=20)
            run(second, seeds=1, events=20)
            self.assertEqual(result['protocol_cases'], 48)
            self.assertEqual(result['observations'], 40)
            for path in first.iterdir():
                self.assertEqual(path.read_bytes(), (second/path.name).read_bytes())
