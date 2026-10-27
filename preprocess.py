"""Normalize security artifacts in a UTF-8 CSV using ANCHOR."""

import argparse
import csv
from pathlib import Path

from standardizer import STANDARDIZATION_FUNCTIONS, standardize


def preprocess(input_path: Path, output_path: Path) -> int:
    """Preserve input columns and append normalized_artifact; never overwrite."""
    with input_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        required = {"artifact_type", "raw_artifact"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("Input CSV requires artifact_type and raw_artifact columns.")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Input CSV contains duplicate column names.")
        if "normalized_artifact" in reader.fieldnames:
            raise ValueError("Input already contains a normalized_artifact column.")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("x", encoding="utf-8", newline="") as destination:
            writer = csv.DictWriter(
                destination, fieldnames=[*reader.fieldnames, "normalized_artifact"]
            )
            writer.writeheader()
            count = 0
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"Malformed CSV record ending at line {reader.line_num}.")
                kind = row["artifact_type"].strip().lower()
                if kind not in STANDARDIZATION_FUNCTIONS:
                    raise ValueError(
                        f"Unsupported artifact_type at line {reader.line_num}: {kind!r}."
                    )
                row["normalized_artifact"] = standardize(row["raw_artifact"], kind)
                writer.writerow(row)
                count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Input artifact CSV")
    parser.add_argument("--output", required=True, type=Path, help="New output CSV path")
    args = parser.parse_args()
    try:
        count = preprocess(args.input, args.output)
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"Normalized {count} artifacts to {args.output}")


if __name__ == "__main__":
    main()
