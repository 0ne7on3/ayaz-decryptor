from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DocumentationTests(unittest.TestCase):
    def test_gpu_throughput_names_the_test_hardware(self):
        for relative_path in ("README.md", "cuda/README.md"):
            with self.subTest(path=relative_path):
                content = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn("28–30 billion candidates/s", content)
                self.assertIn("NVIDIA GeForce RTX 5090", content)
                self.assertNotIn("CPU-only", content)

        overview = (ROOT / "README.md").read_text(encoding="utf-8")
        cuda_readme = (ROOT / "cuda/README.md").read_text(encoding="utf-8")
        self.assertIn("cuda/README.md#build-and-tests", overview)
        self.assertIn("## Build and tests", cuda_readme)


if __name__ == "__main__":
    unittest.main()
