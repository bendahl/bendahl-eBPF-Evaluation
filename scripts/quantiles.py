# This utility script was used to calculate quantiles for different metrics.
import statistics as s

# Enter values to be used as a basis of the quantile calculation in the list below
values = [86, 89, 97, 81, 96, 36]

print([round(x, 2) for x in s.quantiles(values, n=3)])
