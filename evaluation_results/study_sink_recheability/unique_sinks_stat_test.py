import numpy as np
import pandas as pd
import copy
import os

from scipy import stats
from scipy.stats.mstats import f_oneway

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker


max_sinks_for_app = {
    "com.habitrpg.android.habitica": 30,
    "com.radioplayer.mobile": 20,
    "de.komoot.android": 80,
    "com.funnmedia.waterminder": 22,
    "com.pallo.passiontimerscoped": 40,
    "org.iggymedia.periodtracker": 80,
    "com.google.android.wearable.app": 50,
    "au.com.auspost.android": 30,
    "com.calm.android": 29,
    "com.outdooractive.Outdooractive": 45
}


def vargha_delaney_paired(x, y):
    more = same = 0.0
    for i in range(len(x)):
        if x[i] == y[i]:
            same += 1
        elif x[i] > y[i]:
            more += 1
    return (more + 0.5 * same) / len(x)


def compute_statistic_test(dict_for_table, type_measure, out_file_name, row_name, algo1_name, algo2_name, mean_algo_1, mean_algo_2):
    (w_rl, p_rl) = stats.shapiro(np.array(mean_algo_1) - np.mean(mean_algo_1))
    (w_random, p_random) = stats.shapiro(np.array(mean_algo_2) - np.mean(mean_algo_2))
    if np.mean(mean_algo_1) < np.mean(mean_algo_2):
        looser_algo = algo1_name
        winner_algo = algo2_name
    else:
        looser_algo = algo2_name
        winner_algo = algo1_name
    if p_rl > 0.05 and p_random > 0.05:
        _, p = f_oneway(mean_algo_1, mean_algo_2)
        with open(os.path.join("unique_sinks", f"stat_tests_{out_file_name}.txt"), "a+") as f:
            if p < 0.05:
                f.write(f"{row_name} - ANOVA: the two algorithms have different behaviors\n\n")
                eff_size = (np.mean(mean_algo_1) - np.mean(mean_algo_2)) / np.sqrt(
                    np.std(np.array(mean_algo_1) ** 2 + np.std(mean_algo_2) ** 2) / 2.0)
                if p < 0.05:
                    if np.abs(eff_size) < 0.2:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["N"].add(looser_algo)
                    elif np.abs(eff_size) < 0.5:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["S"].add(looser_algo)
                    elif np.abs(eff_size) < 0.8:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["M"].add(looser_algo)
                    else:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["L"].add(looser_algo)
            else:
                f.write(f"{row_name} - ANOVA: the two algorithms perform the same\n\n")
    else:
        (t, p) = stats.wilcoxon(mean_algo_1, mean_algo_2)
        with open(os.path.join("unique_sinks", f"stat_tests_{out_file_name}.txt"), "a+") as f:
            if p < 0.05:
                f.write(f"{row_name} - WILCOXON: the two algorithms have different behaviors\n\n")
                eff_size = vargha_delaney_paired(mean_algo_1, mean_algo_2)
                if p < 0.05:
                    if 2 * np.abs(eff_size - 0.5) < 0.147:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["N"].add(looser_algo)
                    elif 2 * np.abs(eff_size - 0.5) < 0.33:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["S"].add(looser_algo)
                    elif 2 * np.abs(eff_size - 0.5) < 0.474:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["M"].add(looser_algo)
                    else:
                        dict_for_table[row_name][f"eff_size_{type_measure}"][winner_algo]["L"].add(looser_algo)
            else:
                f.write(f"{row_name} - WILCOXON: the two algorithms perform the same\n\n")


def plot_distributions(overall_mean_per_algo, stats_dict):
    fig, (ax1, ax2) = plt.subplots(ncols=2, figsize=(18, 5), gridspec_kw={'width_ratios': [1, 2]})

    colors = ['r', 'g', 'b']
    fontsize = 15
    fontsize_legend = 15
    tick_labelsize = 15

    for algo in overall_mean_per_algo:
        label = algo
        if label == "Rand":
            label = "Black-box Fuzzer"
        ax1.scatter(range(len(overall_mean_per_algo[algo])), overall_mean_per_algo[algo], label=label, color=colors.pop(), s=40)

    ax1.set_xlabel('Episode', fontsize=fontsize)
    ax1.set_ylabel('Cumulative # Unique Sinks Reached', fontsize=fontsize)
    ax1.tick_params(axis='both', which='major', labelsize=tick_labelsize)
    ax1.set_xticks(range(10))
    ax1.legend(loc='upper left', fontsize=fontsize_legend)
    ax1.grid(True)

    bar_width = 0.2
    num_apps = len(stats_dict)
    indices = np.arange(num_apps)

    algorithms = ['SAC', 'TRPO', 'Rand']
    colors_hist = ['r', 'g', 'b', 'y']

    for i, algo in enumerate(algorithms):
        label = algo
        if label == "Rand":
            label = "Black-box Fuzzer"

        algo_data = [min(max(stats_dict[app][algo]["mean"]), max_sinks_for_app[app]) / max_sinks_for_app[app] * 100 for app in stats_dict]
        ax2.bar(indices + i * bar_width, algo_data, bar_width, label=label, color=colors_hist[i])

    ax2.set_xticks(indices + bar_width)
    app_labels = [f"App {i + 1}" for i in range(num_apps)]
    ax2.set_xticklabels(app_labels, fontsize=tick_labelsize)
    ax2.yaxis.set_major_formatter(mticker.FuncFormatter(lambda y, _: f'{int(y)}%'))

    ax2.set_xlabel('App', fontsize=fontsize)
    ax2.set_ylabel('% Sinks Covered', fontsize=fontsize)
    ax2.tick_params(axis='both', which='major', labelsize=tick_labelsize)

    ax2.legend(loc='center right', fontsize=fontsize_legend)
    ax2.grid(True)

    plt.tight_layout()
    plt.savefig(os.path.join("unique_sinks", "unique_sinks_for_episode.png"), format='png')


if __name__ == "__main__":
    iterations = 10
    episodes = 10
    algos = ["SAC", "TRPO", "Rand"]

    stats_dict = dict()
    app_algo_iteration_episodes_dict = dict()
    iteration_algo_files_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "unique_sinks", "results")
    for iteration_algo_file in os.listdir(iteration_algo_files_path):
        iteration_algo = pd.read_csv(os.path.join(iteration_algo_files_path, iteration_algo_file)).set_index(["app"]).to_dict('index')
        algo_file = ""
        algo_file_original = ""
        for algo in algos:
            if algo.lower() in iteration_algo_file:
                algo_file = algo
                algo_file_original = iteration_algo_file.split("_")[2]
                break
        iteration_file = int(iteration_algo_file.split(algo_file_original + "_")[1].split(".csv")[0]) - 1
        for app in iteration_algo:
            if app not in app_algo_iteration_episodes_dict:
                app_algo_iteration_episodes_dict[app] = dict()
            if algo_file not in app_algo_iteration_episodes_dict[app]:
                app_algo_iteration_episodes_dict[app][algo_file] = []
                for iteration in range(iterations):
                    app_algo_iteration_episodes_dict[app][algo_file].append([0 for _ in range(episodes)])

            for column in iteration_algo[app]:
                if column.startswith("episode "):
                    episode_idx = int(column.split(" ")[1])
                    episode_value = int(iteration_algo[app][column].split("/")[0])
                    app_algo_iteration_episodes_dict[app][algo_file][iteration_file][episode_idx] = episode_value

    for app in app_algo_iteration_episodes_dict:
        for algo in app_algo_iteration_episodes_dict[app]:
            if app not in stats_dict:
                stats_dict[app] = dict()
            if algo not in stats_dict[app]:
                stats_dict[app][algo] = dict()
            episode_sinks_num = [[0 for _ in range(iterations)] for _ in range(episodes)]
            for episode in range(episodes):
                for iteration in range(iterations):
                    episode_sinks_num[episode][iteration] = app_algo_iteration_episodes_dict[app][algo][iteration][episode]
            mean_vector = [0 for _ in range(episodes)]
            for episode in range(episodes):
                mean_vector[episode] = np.mean(episode_sinks_num[episode])
            area_vector = [0 for _ in range(iterations)]
            for iteration in range(iterations):
                area_vector[iteration] = np.trapz(app_algo_iteration_episodes_dict[app][algo][iteration], dx=1)
            stats_dict[app][algo]["mean"] = mean_vector
            stats_dict[app][algo]["area"] = area_vector

    overall_mean_sink_algo = {algo: [] for algo in algos}
    for algo in algos:
        for episode in range(episodes):
            mean_episode = []
            for app_name in stats_dict:
                mean_episode.append(stats_dict[app_name][algo]["mean"][episode])
            overall_mean_sink_algo[algo].append(np.mean(mean_episode))

    plot_distributions(overall_mean_sink_algo, stats_dict)

    dict_row = {f"mean_{algo}": "" for algo in algos}
    dict_row.update({f"area_{algo}": "" for algo in algos})
    eff_size_dict = {algo: {"N": set(), "S": set(), "M": set(), "L": set()} for algo in algos}
    dict_row["eff_size_mean"] = copy.deepcopy(eff_size_dict)
    dict_row["eff_size_area"] = copy.deepcopy(eff_size_dict)

    dict_for_table = {app_name: copy.deepcopy(dict_row) for app_name in stats_dict}
    dict_for_table["Overall"] = copy.deepcopy(dict_row)

    for app_name in stats_dict:
        for algo in stats_dict[app_name]:
            dict_for_table[app_name][f"mean_{algo}"] = str(format(np.mean(stats_dict[app_name][algo]["mean"]), ".2f"))
            dict_for_table[app_name][f"area_{algo}"] = str(format(np.mean(stats_dict[app_name][algo]["area"]), ".2f"))

    for algo in algos:
        dict_for_table["Overall"][f"mean_{algo}"] = str(format(np.mean([np.mean(stats_dict[app_name][algo]["mean"]) for app_name in stats_dict]), ".2f"))
        dict_for_table["Overall"][f"area_{algo}"] = str(format(np.mean([np.mean(stats_dict[app_name][algo]["area"]) for app_name in stats_dict]), ".2f"))

    for app_name in stats_dict:
        couples_done = set()
        for algo1 in algos:
            for algo2 in algos:
                if algo1 != algo2 and (algo1, algo2) not in couples_done and (algo2, algo1) not in couples_done:
                    couples_done.add((algo1, algo2))
                    mean_algo1 = stats_dict[app_name][algo1]["mean"]
                    mean_algo2 = stats_dict[app_name][algo2]["mean"]
                    compute_statistic_test(dict_for_table, "mean", f"mean_{algo1}_{algo2}", app_name, algo1, algo2, mean_algo1, mean_algo2)

    for app_name in stats_dict:
        couples_done = set()
        for algo1 in algos:
            for algo2 in algos:
                if algo1 != algo2 and (algo1, algo2) not in couples_done and (algo2, algo1) not in couples_done:
                    couples_done.add((algo1, algo2))
                    area_algo1 = stats_dict[app_name][algo1]["area"]
                    area_algo2 = stats_dict[app_name][algo2]["area"]
                    compute_statistic_test(dict_for_table, "area", f"area_{algo1}_{algo2}", app_name, algo1, algo2, area_algo1, area_algo2)

    for app_name in stats_dict:
        couples_done = set()
        for algo1 in algos:
            for algo2 in algos:
                if algo1 != algo2 and (algo1, algo2) not in couples_done and (algo2, algo1) not in couples_done:
                    couples_done.add((algo1, algo2))
                    mean_algo1 = [np.mean(stats_dict[app_name][algo1]["mean"]) for app_name in stats_dict]
                    mean_algo2 = [np.mean(stats_dict[app_name][algo2]["mean"]) for app_name in stats_dict]
                    compute_statistic_test(dict_for_table, "mean", f"overall_mean_{algo1}_{algo2}", "Overall", algo1, algo2, mean_algo1, mean_algo2)

    for app_name in stats_dict:
        couples_done = set()
        for algo1 in algos:
            for algo2 in algos:
                if algo1 != algo2 and (algo1, algo2) not in couples_done and (algo2, algo1) not in couples_done:
                    couples_done.add((algo1, algo2))
                    mean_algo1 = [np.mean(stats_dict[app_name][algo1]["area"]) for app_name in stats_dict]
                    mean_algo2 = [np.mean(stats_dict[app_name][algo2]["area"]) for app_name in stats_dict]
                    compute_statistic_test(dict_for_table, "area", f"overall_area_{algo1}_{algo2}", "Overall", algo1, algo2, mean_algo1, mean_algo2)

    for app_name in dict_for_table:
        for algo in algos:
            eff_sizes = ""
            for eff_size_label in dict_for_table[app_name]["eff_size_mean"][algo]:
                algos_eff_size = dict_for_table[app_name]["eff_size_mean"][algo][eff_size_label]
                if len(algos_eff_size) > 0:
                    if eff_sizes != "":
                        eff_sizes += "; "
                    eff_sizes += f"{eff_size_label}({';'.join(dict_for_table[app_name]['eff_size_mean'][algo][eff_size_label])})"
            space = ""
            if eff_sizes != "":
                space = " "
            dict_for_table[app_name][f"mean_{algo}"] = dict_for_table[app_name][f"mean_{algo}"] + space + eff_sizes

            eff_sizes = ""
            for eff_size_label in dict_for_table[app_name]["eff_size_area"][algo]:
                algos_eff_size = dict_for_table[app_name]["eff_size_area"][algo][eff_size_label]
                if len(algos_eff_size) > 0:
                    if eff_sizes != "":
                        eff_sizes += "; "
                    eff_sizes += f"{eff_size_label}({';'.join(dict_for_table[app_name]['eff_size_area'][algo][eff_size_label])})"
            space = ""
            if eff_sizes != "":
                space = " "
            dict_for_table[app_name][f"area_{algo}"] = dict_for_table[app_name][f"area_{algo}"] + space + eff_sizes
        del dict_for_table[app_name]["eff_size_mean"]
        del dict_for_table[app_name]["eff_size_area"]

    df = pd.DataFrame.from_dict(dict_for_table, orient='index')
    df.reset_index(names=["app"]).to_csv(os.path.join("unique_sinks", "final_table.csv"), index=False)
