// load google charts library
google.load("visualization", "1", {packages:["corechart"]});

// data
var data, options, chart;

// data
var data2, options2, chart2;

var i = 0;

/* initialize chart1 data */
function drawChart(data, options) {
    var chart = new google.visualization.LineChart(
                        document.getElementById('data-container'));
    chart.draw(data, options);
    return(chart);
}

/* initialize chart2 data */
function drawChart2(data, options) {
    var chart = new google.visualization.LineChart(
                        document.getElementById('data-container2'));
    chart.draw(data, options);
    return(chart);
}

/* update the chart1 data */
function updateChart(chat, email, file_transfer, p2p, 
                     streaming, voip, web_browsing) {
    i = (i + 1);

    data.addRow([
        ""+i,
        chat, 
        email,
        file_transfer, 
        p2p,
        streaming,
        voip,
        web_browsing
    ]);

    // Check number of row getNumberOfRows()
    if(data.getNumberOfRows() > 20) {
        data.removeRow(0);
    }

    chart.draw(data, options);
}

/* update the chart2 data */
function updateChart2(packet_length) {
    data2.addRow([
        ""+i,
        packet_length
    ]);

    // Check number of row getNumberOfRows()
    if(data2.getNumberOfRows() > 20) {
        data2.removeRow(0);
    }

    chart2.draw(data2, options2);
}

$(function() {

    data = google.visualization.arrayToDataTable([
        ["Time", "Chat", "Email", "File Transfer", 
         "P2P", "Streaming", "VoIP", "Web Browsing"],
        ['0', 0, 0, 0, 0, 0, 0, 0],
    ]);

    data2 = google.visualization.arrayToDataTable([
        ['Time', 'Packet length'],
        ['0', 0],
    ]);
    
    options = {
        title: 'Live classification with SPPNet',
        "curveType": "function",
        vAxis : {
            title : 'Test',
            viewWindow: {
                min: 0,
                max: 1
            }
        },
    };

    options2 = {
        title: 'Live packet length',
        "curveType": "function",
    };

    chart = drawChart(data, options);
    chart2 = drawChart2(data2, options2);
});


/* reset charts */
function reset(){
    i = 0;
    
    data = google.visualization.arrayToDataTable([
        ["Time", "Chat", "Email", "File Transfer", 
         "P2P", "Streaming", "VoIP", "Web Browsing"],
        ['0', 0, 0, 0, 0, 0, 0, 0],
    ]);

    data2 = google.visualization.arrayToDataTable([
        ['Time', 'Packet_length'],
        ['0', 0],
    ]);

    options = {
        height: 300,
        width: '100%',
        title: 'Live classification with SPPNet',
        "curveType": "function",
    };

    options2 = {
        height: 300,
        width: '100%',
        title: 'Live packet length',
        "curveType": "function",
    };

    chart = drawChart(data, options);
    chart2 = drawChart2(data2, options2);
}
