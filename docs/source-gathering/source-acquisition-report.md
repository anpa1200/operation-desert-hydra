# Source Acquisition Report

Date: 2026-05-22

This folder contains the raw acquisition pass for the Operation Desert Hydra source list.

## Output Location

```text
docs/source-gathering/raw-sources/
```

Each source has its own folder:

```text
NN-source-title/
├── headers.txt
├── metadata.json
├── source.html | source.pdf | source.txt
├── source.txt
└── fallback-reader.txt   # only when a reader fallback was needed
```

## Acquisition Summary

- Source list entries processed: 71
- Source folders retained after quality cleanup: 65
- Source folders deleted after failing quality check: 6
- Text extraction attempted for every source.
- PDFs were saved as `source.pdf` and converted to `source.txt` when possible.
- HTML pages were saved as `source.html` and converted to `source.txt`.
- Reader fallbacks were saved for sources that returned anti-bot or access-denied pages.

## Important Notes

These files are raw research material. They are not validated CTI data.

Before promotion into `data/sources.yaml`, each source still needs:

- URL validation
- publisher validation
- publication-date validation
- actor-claim validation
- duplicate-source handling
- evidence-label assignment
- source reliability assessment
- unsupported-claim removal

## Deleted After Quality Check

The following acquired files were removed because the saved local copy was not full, correct, or high-quality enough for review.

| Source | Reason | Replacement / Better Source |
|---|---|---|
| 04 CISA MuddyWater alert | weak duplicate and direct fetch blocked | 05 advisory fallback, 07 real PDF mirror |
| 06 CISA AA22-055A PDF | `source.pdf` was an HTML access-denied page | 07 real PDF mirror |
| 20 ClearSky Operation Quicksand blog | anti-bot/minimal content only | source list keeps URL; reacquire manually if needed |
| 21 ClearSky Operation Quicksand PDF | `source.pdf` was anti-bot HTML; fallback only | source list keeps URL; reacquire manually if needed |
| 25 HarfangLab Atera campaign | anti-bot page only; fallback not useful | source list keeps URL; reacquire manually/browser capture needed |
| 52 CISA AA23-335A PDF | `source.pdf` was an HTML access-denied page | 51 advisory page fallback, source list keeps official URL |

## Blocked Or Partially Blocked Sources Retained

Some sources returned access-denied or anti-bot pages to direct curl requests. Where possible, a text fallback was saved as `fallback-reader.txt`.

| Source | Direct Fetch | Fallback |
|---|---:|---|
| 05 CISA AA22-055A advisory page | 403 | useful fallback saved |
| 16 INCD MuddyWater page | 403 | useful fallback saved; source 17 has direct PDF |
| 27 SC Media brief | 403 | useful fallback saved |
| 49 CISA Iran threat overview | 403 | useful fallback saved |
| 50 CISA Iran publications | 403 | useful fallback saved |
| 51 CISA AA23-335A page | 403 | useful fallback saved |

## Next Step

Create a reviewed source register:

```text
data/sources.yaml
```

Only promote sources after confirming that the saved content is useful and the source claims are supported by the original publisher.
