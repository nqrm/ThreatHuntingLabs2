### Подключение нужных пакетов

    library(arrow)
    library(dplyr)
    library(stringr)
    library(lubridate)
    library(ggplot2)

### Импорт датасета

    dataset <- arrow::read_csv_arrow("gowiththeflow_20190826.csv",schema = schema(timestamp=int64(),src=utf8(),dst=utf8(),port=uint32(),bytes=uint32())) %>% collect()

# Задание 1: Найдите утечку данных из Вашей сети

## Важнейшие документы с результатами нашей исследовательской деятельности в области создания вакцин скачиваются в виде больших заархивированных дампов. Один из хостов в нашей сети используется для пересылки этой информации – он пересылает гораздо больше информации на внешние ресурсы в Интернете, чем остальные компьютеры нашей сети. Определите его IP-адрес.

### Определение IP-адреса, который пересылает больше информации на внешние ресурсы.

### Ответ на задание - 13.37.84.125

    dataset %>%
      select(src,dst,bytes) %>%
      mutate(outside_traffic = str_detect(src,"^((12|13|14)\\.)") & !str_detect(dst,"^((12|13|14)\\.)")) %>%
      filter(outside_traffic == TRUE) %>%
      group_by(src) %>%
      summarise(total_bytes = sum(bytes)) %>%
      arrange(desc(total_bytes)) %>%
      head(1) %>%
      collect()

    ## # A tibble: 1 × 2
    ##   src          total_bytes
    ##   <chr>              <dbl>
    ## 1 13.37.84.125 10625497574

# Задание 2: Надите утечку данных 2

## Другой атакующий установил автоматическую задачу в системном планировщике cron для экспорта содержимого внутренней wiki системы. Эта система генерирует большое количество траффика в нерабочие часы, больше чем остальные хосты. Определите IP этой системы. Известно, что ее IP адрес отличается от нарушителя из предыдущей задачи.

### Построив графики распределения количества пакетов и данных за каждый час, видно, что:

      1. С 16 часов резко возрастает сетевая активность и остается примерно на одном уровне до 24 часа;
      2. С 0 часа до 15 сетевая активность, так же равномерна, но значительно меньше чем в часы 16-24;

### Предполагая, что в рабочее время сетевая активность больше чем в нерабочее, можно сделать вывод, что нерабочие часы - с 0 по 15.

### Количество пакетов в каждый час
![Image alt](https://github.com/nqrm/ThreatHuntingLabs2/blob/master/LAB1/images/packets_per_hour.bmp)

### Количество данных в каждый час
![Image alt](https://github.com/nqrm/ThreatHuntingLabs2/blob/master/LAB1/images/data_per_hour.bmp)

### Ответ на задание - 12.55.77.96

    dataset %>%
      select(timestamp, src, dst, bytes) %>%
      mutate(outside_traffic = (str_detect(src,"^((12|13|14)\\.)") & !str_detect(dst,"^((12|13|14)\\.)")), hour = hour(as_datetime(timestamp/1000))) %>%
      filter(outside_traffic == TRUE, hour >= 0 & hour <= 15) %>%
      group_by(src) %>%
      summarise(total_bytes = sum(bytes),) %>%
      arrange(desc(total_bytes)) %>%
      head(10) %>%
      collect()

    ## # A tibble: 10 × 2
    ##    src          total_bytes
    ##    <chr>              <int>
    ##  1 13.37.84.125   731158032
    ##  2 12.55.77.96    289566918
    ##  3 13.48.72.30    120862595
    ##  4 14.51.30.86    116752466
    ##  5 12.59.25.34    115533918
    ##  6 14.51.75.107   112816919
    ##  7 12.56.32.111   111708846
    ##  8 12.58.68.102   108870195
    ##  9 14.57.50.29    108788348
    ## 10 13.39.46.94    107736632

      # График распределения отправленных пакетов в каждый час
      #group_by(hour) %>%
      #summarise(packets=n()) %>%
      #collect()
      #ggplot(., aes(x=hour,y=packets),) + geom_histogram(stat="identity", color="black",fill="green")

# Задание 3: Найдите утечку данных 3

### Еще один нарушитель собирает содержимое электронной почты и отправляет в Интернет используя порт, который обычно используется для другого типа трафика. Атакующий пересылает большое количество информации используя этот порт, которое нехарактерно для других хостов, использующих этот номер порта. Определите IP этой системы. Известно, что ее IP адрес отличается от нарушителей из предыдущих задач.

### 1. Сколько всего данных отправлено на каждый порт
![Image alt](https://github.com/nqrm/ThreatHuntingLabs2/blob/master/LAB1/images/data_per_port.png)

### 2. Исходя из графика, нужно найти только те порты, на которые отправлено меньше всего данных

    dataset %>%
      select(src, dst, bytes,port) %>%
      mutate(outside_traffic = (str_detect(src,"^((12|13|14)\\.)") & !str_detect(dst,"^((12|13|14)\\.)"))) %>%
      filter(outside_traffic == TRUE) %>%
      group_by(port) %>%
      summarise(total_data=sum(bytes)) %>%
      filter(total_data < 5*10^9) %>%
      select(port) %>%
      collect() -> ports

    ports <- unlist(ports)
    ports <- as.vector(ports,'numeric')

### 3. Выбрать данные с нужными номерами портов

    dataset %>%
      select(src, dst, bytes,port) %>%
      mutate(outside_traffic = (str_detect(src,"^((12|13|14)\\.)") & !str_detect(dst,"^((12|13|14)\\.)"))) %>%
      filter(outside_traffic == TRUE) %>%
      filter(port %in% ports) %>%
      group_by(src,port) %>%
      summarise(total_bytes=sum(bytes)) %>%
      arrange(desc(port)) %>%
      collect() -> df

### 4. Порты с маскимальным кол-вом данных

    df %>%
      group_by(src, port) %>%
      summarise(total_data=sum(total_bytes)) %>%
      arrange(desc(total_data)) %>%
      head(10) %>%
      collect()

    ## # A tibble: 10 × 3
    ## # Groups:   src [3]
    ##    src           port total_data
    ##    <chr>        <int>      <int>
    ##  1 13.37.84.125    36 2070876332
    ##  2 13.37.84.125    95 2031985904
    ##  3 13.37.84.125    21 2027501066
    ##  4 13.37.84.125    78 2018366254
    ##  5 13.37.84.125    32 1989408807
    ##  6 12.55.77.96     31  233345180
    ##  7 13.48.72.30     26    2468348
    ##  8 13.48.72.30     61    2465805
    ##  9 13.48.72.30     77    2453566
    ## 10 13.48.72.30     79    2421971

### 5. Количество хостов к портам

    df %>%
      group_by(port) %>%
      summarise(hosts=n()) %>%
      arrange(hosts) %>%
      head(10) %>%
      collect()

    ## # A tibble: 10 × 2
    ##     port hosts
    ##    <int> <int>
    ##  1    21     1
    ##  2    31     1
    ##  3    32     1
    ##  4    36     1
    ##  5    78     1
    ##  6    95     1
    ##  7    51    24
    ##  8    22  1000
    ##  9    23  1000
    ## 10    25  1000

### 6. Из предыдущих пунктов следует вывод, что ip-адрес злоумышленника 12.55.77.96, а порт 31, т.к. из таблицы в 5 пункте видно, что 31 порт использовал только 1 хост и в тоже время из таблицы в 4 пункте видно, что больше всего данных было передано именно по этому порту

    df %>%
      filter(port == 31) %>%
      group_by(src) %>%
      summarise(total_data=sum(total_bytes)) %>%
      collect()

    ## # A tibble: 1 × 2
    ##   src         total_data
    ##   <chr>            <int>
    ## 1 12.55.77.96  233345180

### Ответ на задание - 12.55.77.96
