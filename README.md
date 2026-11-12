# AI tool vulnerabilities

GitHub-reviewed security advisories for 17 open-source AI tools, January 2023 onward.

Chart and write-up: [birdyfoot.com](https://birdyfoot.com)

## Files

- `ai_tool_vulnerabilities.csv`: one row per advisory, linked to GitHub
- `build_dataset.py`: rebuilds the CSV from the [GitHub Advisory Database](https://github.com/github/advisory-database)

## Rebuild

```
python3 build_dataset.py
```

Python 3 only, no dependencies.

## Notes

- Counts are reported flaws.
- Flaw types are BirdyFoot's grouping of CWE IDs. The tool list and mapping are at the top of the script.

Source data: GitHub Advisory Database (CC-BY 4.0). Analysis: BirdyFoot Security.
