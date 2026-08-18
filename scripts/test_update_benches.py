import json
import tempfile
import unittest
from pathlib import Path

from update_benches import load_results, read_criterion_results, render_markdown, render_svg


class UpdateBenchesTests(unittest.TestCase):
    def write_criterion_result(self, root: Path, name: str, median: float, elements: int):
        result_dir = root / name / "new"
        result_dir.mkdir(parents=True)
        (result_dir / "estimates.json").write_text(
            json.dumps({"median": {"point_estimate": median}})
        )
        (result_dir / "benchmark.json").write_text(
            json.dumps(
                {
                    "full_id": name,
                    "throughput": {"Elements": elements},
                }
            )
        )

    def test_reads_criterion_element_throughput(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_criterion_result(root, "group/bench/100", 2_000_000, 100)
            measurements = read_criterion_results(root)
            self.assertEqual(measurements[0].name, "group/bench/100")
            self.assertEqual(measurements[0].median_nanoseconds, 2_000_000)
            self.assertEqual(measurements[0].elements_per_second, 50_000)

    def test_rejects_missing_criterion_results(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no Criterion"):
                read_criterion_results(Path(directory))

    def test_loads_and_renders_results_in_pr_order(self):
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
                            "measurements": [
                                {
                                    "name": "group/bench/100",
                                    "median_nanoseconds": 2_000_000,
                                    "elements_per_second": 50_000,
                                }
                            ],
                        }
                    )
                )
            results = load_results(root)
            self.assertEqual([result.pr for result in results], [3, 20])
            self.assertIn("PR #3", render_svg(results))
            self.assertIn("| [#3]", render_markdown(results))


if __name__ == "__main__":
    unittest.main()
