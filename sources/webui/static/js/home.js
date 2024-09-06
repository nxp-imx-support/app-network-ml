
// Get inference report and update charts.
function get_all_infer_report() {
    var url_prefix = window.location.origin;
    $.ajax({
        url: url_prefix + "/get_status",
        type: "get",
        success: function(result) {
          console.log(result);
          update_display(result);
        },
        error: function() {
          console.log("get report error.");
        }
    });
}

function update_display(msg) {
    // Update the status information at the bottom.
    var dpdk_status = $("#dpdk-status");
    dpdk_status.empty();
    var rx_pkts = "<li>RX packets: " + msg["cur_packets_rx"] + "</li>";
    var tx_pkts = "<li>TX packets: " + msg["cur_packets_tx"] + "</li>";
    var speed = 0;
    if (msg["time_period"] != 0) {
        speed = (msg["cur_packets_rx"] - msg["previous_packets_rx"] + msg["cur_packets_tx"] - msg["previous_packets_tx"]) / msg["time_period"];
        speed = speed.toFixed(2);
    }
    var throughput = "<li>Throughput: " + speed + " pps</li>";
    dpdk_status.html(rx_pkts + tx_pkts + throughput);

    var model_status = $("#model-status");
    model_status.empty();
    speed = 0;
    if (msg["infer_time"] != 0)
        speed = (msg["infer_samples"] / msg["infer_time"]).toFixed(2);
    var infer_speed = "<li>Inference speed: " + speed + " pps</li>";
    var npu_used = "<li>NPU: ";
    if (msg["npu_used"] == 1)
        npu_used += "Yes</li>";
    else
        npu_used += "No</li>";
    model_status.html(infer_speed + npu_used);

    // Update connections table
    var connections_table = $("#connections-table tbody");
    connections_table.empty();

    $.each(msg["ip_connections_list"], function(idx, row){
        let tr = $("<tr></tr>");
        let col1 = "<td>" + row[0] + "</td>";
        let col2 = "";
        if (row[1] == 1)
            col2 = "<td class=\"text-warning\">Yes</td>";
        else
            col2 = "<td class=\"text-info\">No</td>";
        tr.html(col1 + col2);
        connections_table.append(tr);
    });

    // Update score table
    var score_table = $("#score-table tbody");
    score_table.empty();
    var tr1 = $("<tr></tr>");
    tr1.append("<td>" + msg["ddos_cnt"] + "</td>");
    tr1.append("<td></td>");
    tr1.append("<td>" + msg["benign_cnt"] + "</td>");
    score_table.append(tr1);

    var tr2 = $("<tr></tr>");
    tr2.append("<td>DDoS rate:</td>");
    var rate = 0;
    rate = Math.floor(msg["ddos_cnt"] / msg["total_cnt"] * 100);
    tr2.append("<td>" + rate + "%</td>");
    score_table.append(tr2);
    
}


$(document).ready(function (){
    setInterval(get_all_infer_report, 2000);
});