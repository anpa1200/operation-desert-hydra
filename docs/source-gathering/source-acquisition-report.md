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
- Source folders created: 71
- Raw files saved: 71
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

## Blocked Or Partially Blocked Sources

Some sources returned access-denied or anti-bot pages to direct curl requests. Where possible, a text fallback was saved as `fallback-reader.txt`.

| Source | Direct Fetch | Fallback |
|---|---:|---|
| 04 CISA MuddyWater alert | 403 | weak duplicate of source 05 |
| 05 CISA AA22-055A advisory page | 403 | useful fallback saved |
| 06 CISA AA22-055A PDF | 403 | useful fallback saved; source 07 has direct PDF mirror |
| 16 INCD MuddyWater page | 403 | useful fallback saved; source 17 has direct PDF |
| 20 ClearSky Operation Quicksand blog | anti-bot HTML | weak fallback; source 21 has detailed report fallback |
| 21 ClearSky Operation Quicksand PDF | anti-bot HTML | useful fallback saved |
| 25 HarfangLab Atera campaign | anti-bot HTML | weak fallback only |
| 27 SC Media brief | 403 | useful fallback saved |
| 49 CISA Iran threat overview | 403 | useful fallback saved |
| 50 CISA Iran publications | 403 | useful fallback saved |
| 51 CISA AA23-335A page | 403 | useful fallback saved |
| 52 CISA AA23-335A PDF | 403 | useful fallback saved |

## Next Step

Create a reviewed source register:

```text
data/sources.yaml
```

Only promote sources after confirming that the saved content is useful and the source claims are supported by the original publisher.
