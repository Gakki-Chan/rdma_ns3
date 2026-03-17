#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import matplotlib.pyplot as plt

upper = 0

def plot_plot(filename, m_color, m_label, window_size=1):
	# 读取并解析数据
	timestamps = []
	packet_sizes = []
    
	with open(filename, 'r') as f:
        	for line_num, line in enumerate(f, 1):
            		line = line.strip()
            
            		try:
                		t, size = line.split(',')
                		t = float(t)
                		size = int(size)
                		timestamps.append(t)
                		packet_sizes.append(size)
            		except ValueError:
                		print 'Warnning: line ', line_num, ' error，has jumped.'
                		continue

	# 计算瞬时速率(Mbps)
	rates = []
	time_points = []
	for i in range(1, len(timestamps)):
		delta_t = timestamps[i] - timestamps[i-1]
		# 计算速率: (bytes * 8 bits/byte) / (seconds * 1e6 bits/Mbit) = Mbps
		rate = (packet_sizes[i] * 8) / (delta_t * 1e9)
		rates.append(rate)
		time_points.append(timestamps[i])

	# 可选: 滑动窗口平均平滑数据
	if window_size > 1:
		smoothed_rates = []
		for i in range(len(rates)):
			start = max(0, i - window_size // 2)
			end = min(len(rates), i + window_size // 2 + 1)
			smoothed_rates.append(sum(rates[start:end]) / (end - start))
		rates = smoothed_rates

	# 绘制图表
	plt.plot(time_points, rates, 
		linestyle='-', 
		linewidth=1.5,
		color=m_color,
		label=m_label
	)
	
	# 调整坐标轴范围，忽略后5%的异常值
	if len(rates) > 10:
		sorted_rates = sorted(rates)
		curr_upper = sorted_rates[int(0.995 * len(rates))]
		global upper
		if curr_upper > upper:
			upper = curr_upper
		

# 使用示例
plt.figure(figsize=(12, 6))

plot_plot('agent_1.txt', 'steelblue', 'Normal Flow', window_size=1)
plot_plot('agent_5.txt', 'indianred', 'Attack Flow', window_size=1)

    
plt.xlabel('Time (Seconds)', fontsize=18)
plt.ylabel('FlowRate (Gbps)', fontsize=18)
plt.yticks(size = 16)
plt.xticks(size = 16)
plt.title('Flow Rate Over Time', fontsize=22)
plt.grid(True, linestyle=':', alpha=0.7)
plt.legend(prop={'size'   : 16})

# 调整坐标轴范围，忽略后5%的异常值
plt.ylim(0, upper*1.005)

plt.tight_layout()
    
# 保存图片
output_file = 'Under_Attack.png'
plt.savefig(output_file, dpi=1000)
print 'picture has be saved: ', output_file
    
plt.show()


