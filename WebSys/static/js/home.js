
// Get inference report and update charts.
function get_all_infer_report() {
    var url_prefix = window.location.origin;
    $.ajax({
        url: url_prefix + "/get_all_infer_report",
        type: "post",
        success: function(result) {
          console.log(result);
          draw_performance_bar_chart(result['warmup_time'], result['infer_time']);
          draw_class_rate_pie_chart(result['class_counter']);
          update_statistic_table(result['pkt_cnt'], result['flow_cnt']);
          update_flow_table(result['flow_list']);
        },
        error: function() {
          console.log("get all inference report error.");
        }
    });
}

// Get momentary pkts-time info for updating chart.
function get_pkts_info() {
    var time_list = [];
    var pkts_list = [];
    var url_prefix = window.location.origin;
    // Draw packets processed bar chart
    var pktProChart = echarts.init(document.getElementById('pkt_processed_fig'));
    var pktOpt = {
        title: {
            text: "Networking packets"
        },
        xAxis: {
            type: "category",
            boundaryGap: false,
            data: time_list
        },
        yAxis: {
            boundaryGap: [0, '50%'],
            type: "value",
            name: "packets"
        },
        series: [
            {
                name: "packets",
                type: "line",
                smooth: true,
                symbol: "none",
                stack: "a",
                areaStyle: {
                    normal: {}
                },
                data: pkts_list
            }
        ]
    };
    pktProChart.setOption(pktOpt);

    setInterval(function() {
        $.ajax({
            url: url_prefix + "/get_pkts_now",
            type: "post",
            success: function(result) {
                time_list.push(result["time"]);
                pkts_list.push(result["pkt_num"]);

                if (time_list.length > 20) {
                    time_list.shift();
                    pkts_list.shift();
                }

                update_pkt_processed_chart(pktProChart, time_list, pkts_list);
            },
            error: function() {
                console.log("get packets information error.")
            }
        });
    }, 1000);


}

function update_statistic_table(pkt_cnt, flow_cnt) {
    $("#statistic_table tr:eq(0) td:eq(1)").html(pkt_cnt);
    $("#statistic_table tr:eq(1) td:eq(1)").html(flow_cnt);
}

function update_flow_table(flow_list) {
    var tbody = $("#flow_table tbody");
    tbody.empty();

    $.each(flow_list, function(idx, row) {
        let tr = $("<tr></tr>");
        let col1 = "<td>" + row[0] + ":" + row[1] + "</td>";
        let col2 = "<td>" + row[2] + ":" + row[3] + "</td>";
        let col3 = "<td>" + row[4] + "</td>";
        let col4 = "<td class=\"text-success\"><b>" + row[5] + "</b></td>";
        tr.html(col1 + col2 + col3 + col4);
        tbody.append(tr);
    });
}

function draw_performance_bar_chart(warmup_time, infer_time){
    // Draw performance bar chart
    var perfBarChart = echarts.init(document.getElementById('performance_fig'));
    var perOpt = {
        title: {
            text: 'Inference performance'
        },
        tooltip: {},
        legend: {
            data:['time (ms)']
        },
        xAxis: {
            type: 'value',
            name: "time(ms)",
            nameLocation: "end",
            nameGap: 10,
            boundaryGap: [0, 0.1]
        },
        yAxis: {
            type: 'category',
            data: ['inference', 'warmup']
        },
        series: [{
            name: 'time',
            type: 'bar',
            data: [infer_time, warmup_time],
            itemStyle: {
                normal: {
                    color: function(param) {
                        let color_list = ["#a5d9bf", "#d48265"];
                        return color_list[param.dataIndex];
                    }
                }
            }
        }]
    };
    console.log("infer_time: " + infer_time);
    console.log("warmup_time: " + warmup_time);
    perfBarChart.setOption(perOpt);
}

function draw_class_rate_pie_chart(class_counter){
    // Draw classes rate pie chart.
    var chart_data = [];
    for (let class_label in class_counter){
        chart_data.push({value: class_counter[class_label], name: class_label});
    }
    var classRateChart = echarts.init(document.getElementById("class_details_fig"));
    var clsOpt = {
        title: {
            text: "Classes rate"
        },
        series: {
            type: "pie",
            label: {
                show: true,
                position: "outside",
                formatter: '{b}: {d}%'
            },
            radius: "55%",
            data: chart_data
        }
        
    };
    classRateChart.setOption(clsOpt);
}

function update_pkt_processed_chart(pktProChart, time_list, pkts_list) {
    var new_opt = {
        xAxis: {
            data: time_list
        },
        series: [{
            name: "packets",
            data: pkts_list
        }]
    };
    pktProChart.setOption(new_opt);
}

$(document).ready(function (){
    setInterval(get_all_infer_report, 10000);
    get_all_infer_report();
    get_pkts_info();

});