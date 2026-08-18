import json
import tempfile
import unittest
from pathlib import Path

from update_benches import load_results, parse_log, render_markdown, render_svg


class UpdateBenchesTests(unittest.TestCase):
    def test_parses_benchmark_output(self):
        self.assertEqual(
            parse_log(
                "builder facade: 123456 operations/s\n"
                "representative monomorphised binary: 987654 bytes\n"
            ),
            (123456, 987654),
        )

    def test_loads_results_in_pr_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pr in (20, 3):
                result_dir = root / f"pr-{pr}"
                result_dir.mkdir()
                (result_dir / "result.json").write_text(
                    json.dumps(
                        {
                            "pr": pr,
                            "commit": "abcdef",
                            "recorded_at": "2026-08-18T00:00:00Z",
                            "operations_per_second": 100000 + pr,
                            "binary_bytes": 1000,
                        }
                    )
                )
            results = load_results(root)
            self.assertEqual([result.pr for result in results], [3, 20])
            self.assertIn("PR #3", render_svg(results))
            self.assertIn("| [#3]", render_markdown(results))


if __name__ == "__main__":
    unittest.main()
