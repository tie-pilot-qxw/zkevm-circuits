import pandas as pd  # macos: pip3 install pandas

cstats = './test_data/cpu.stats'  # 定义 CPU 统计数据文件的路径
mstats = './test_data/mem.stats'  # 定义内存统计数据文件的路径


def calc_stats(cstats, mstats):
    '''
    returns 2 dataframes with cpu/mem stats
    returns a dict with average/max cpu and max ram utilization durint the benchmark
    '''
    dfcpu, cpus = load_stats(cstats)
    cpustats, cpu_all_Max, cpu_all_Average = process_cpustats(dfcpu)
    dfmem, _ = load_stats(mstats)
    memstats, max_ram = process_memstats(dfmem)
    sysstat = {
        'cpu_all_Average': cpu_all_Average,
        'cpu_all_Max': cpu_all_Max,
        'cpu_count': cpus,
        'max_ram': f'{max_ram}Gb'
    }

    return cpustats, memstats, sysstat


def load_stats(file):
    '''
    loads raw mem/cpu sar data from csv to dataframe
    '''
    try:
        with open(file, 'r') as filedata:
            filedatalist = [i for i in filedata.read().splitlines()]
            header = [i for i in filedatalist if 'LINUX-RESTART' in i][0]
            cpus = header.split('(')[1].split()[0]
            cpudatalist = [i for i in filedatalist if 'LINUX-RESTART' not in i]
            columns = cpudatalist[0].split(';')
            cpudatalist = [i for i in cpudatalist if 'hostname' not in i]
            df = pd.DataFrame([i.split(';') for i in cpudatalist], columns=columns)
        return df, cpus
    except Exception as e:
        print(e)
        return None


def process_cpustats(statsdf):
    '''
    accepts cpu stats raw data from csv and returns a dataframe for further processing
    '''
    statsdf = statsdf[['timestamp', '%idle']]
    statsdf['%idle'] = pd.to_numeric(statsdf['%idle'])
    statsdf['utilizationall'] = statsdf['%idle'].apply(lambda x: round(float(100) - x, 2))
    statsdf = statsdf[['timestamp', 'utilizationall']]
    # utilizationall 一列的最大值
    cpu_all_Max = statsdf['utilizationall'].max()
    # utilizationall 一列的平均值
    cpu_all_Average = statsdf['utilizationall'].mean()
    return statsdf, cpu_all_Max, cpu_all_Average


def process_memstats(df):
    '''
    accepts ram stats raw data and returns a dataframe for further processing
    '''
    statsdf = df[['timestamp', 'kbmemused']]
    statsdf['kbmemused'] = pd.to_numeric(statsdf['kbmemused'])
    statsdf['utilizationgb'] = statsdf['kbmemused'].apply(lambda x: round(x / float(1000000), 2))
    statsdf = statsdf[['timestamp', 'utilizationgb']]
    max_ram = statsdf['utilizationgb'].max()
    return statsdf, max_ram


def main():
    # 计算 CPU 和内存的统计数据，
    # cpustats 和 memstats 是对CPU使用率和内存使用率完整的数据记录，可以用于grafana数据展示
    # sysstat 是最终结果展示，包含cpu平均使用率、最大使用率、cpu个数、最大内存使用率
    cpustats, memstats, sysstat = calc_stats(cstats, mstats)
    print(sysstat)


if __name__ == '__main__':
    main()
