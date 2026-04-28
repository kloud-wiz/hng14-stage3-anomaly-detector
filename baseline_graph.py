import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

hours = ['2026-04-27-23\n(Attack Testing)', '2026-04-28-01\n(Quiet/Normal)']
means = [27.93, 1.63]
stddevs = [10.96, 0.52]

fig, ax = plt.subplots(figsize=(10, 6))
colors = ['#f85149', '#3fb950']
bars = ax.bar(hours, means, color=colors, width=0.4, zorder=3)

# Error bars showing stddev
ax.errorbar(hours, means, yerr=stddevs, fmt='none', color='white',
            capsize=8, capthick=2, elinewidth=2, zorder=4)

# Value labels on bars
for bar, mean, std in zip(bars, means, stddevs):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
            f'mean={mean:.2f}\nstddev={std:.2f}',
            ha='center', va='bottom', color='white', fontsize=10, fontweight='bold')

ax.set_facecolor('#161b22')
fig.patch.set_facecolor('#0d1117')
ax.tick_params(colors='#c9d1d9', labelsize=11)
ax.spines['bottom'].set_color('#30363d')
ax.spines['top'].set_color('#30363d')
ax.spines['left'].set_color('#30363d')
ax.spines['right'].set_color('#30363d')
ax.yaxis.label.set_color('#c9d1d9')
ax.xaxis.label.set_color('#c9d1d9')
ax.title.set_color('#58a6ff')
ax.grid(axis='y', color='#30363d', zorder=0)
ax.set_ylabel('Effective Mean (req/s)', fontsize=12)
ax.set_xlabel('Hour Slot', fontsize=12)
ax.set_title('Baseline Effective Mean — Hourly Slots\nKloudwiz Anomaly Detector', fontsize=14)

plt.tight_layout()
plt.savefig('screenshots/Baseline-graph.png', dpi=150, bbox_inches='tight',
            facecolor='#0d1117')
print("Saved to screenshots/Baseline-graph.png")
