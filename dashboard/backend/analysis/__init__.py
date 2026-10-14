"""On-demand analysis agents that score a run against ground truth.

Kept in the dashboard backend (not the zero-dependency security_pipeline
package) because they depend on the ground-truth resolver and httpx. Results are
cached under security_pipeline_runs/<run>/analysis/<agent>/.
"""
