from datetime import datetime

from rules.brute_force_rules import detect_bruteforce
from rules.anomaly_rules import detect_abnormal_input
from rules.rapid_action_rules import detect_rapid_action

print("===== SOC ENGINE STARTED =====")

# -----------------------------
# Initialize counters
# -----------------------------
fail_count = 0
request_count = 0
all_input_data = []

# -----------------------------
# Read log file
# -----------------------------
with open("logs/auth_logs.txt", "r") as file:
    for line in file:
        line = line.strip()

        # Brute force detection
        if "FAIL" in line:
            fail_count += 1

        # General tracking for other rules
        request_count += 1
        all_input_data.append(line)

# -----------------------------
# Run Detection Rules
# -----------------------------
severity1, message1 = detect_bruteforce(fail_count)
severity2, message2 = detect_abnormal_input(" ".join(all_input_data))
severity3, message3 = detect_rapid_action(request_count)

# -----------------------------
# Create Alerts
# -----------------------------
time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

alert1 = f"{time_now} | {severity1} | {message1} | FAIL_COUNT={fail_count}"
alert2 = f"{time_now} | {severity2} | {message2}"
alert3 = f"{time_now} | {severity3} | {message3}"

# -----------------------------
# Output to terminal
# -----------------------------
print("\n===== SOC ALERTS =====")
print(alert1)
print(alert2)
print(alert3)

# -----------------------------
# Save alerts to file
# -----------------------------
with open("outputs/alerts.txt", "a") as f:
    f.write(alert1 + "\n")
    f.write(alert2 + "\n")
    f.write(alert3 + "\n")
