use qr_pake_protocol_executors::bench_api::tk_pake::{
    execute_tk_pake, perform_tk_pake_client_registration,
};
use qr_pake_protocols::{AvailableVariants, TkClient, TkServer};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rust_xlsxwriter::{Workbook, Worksheet};
use stats_ci::{
    mean::{Arithmetic, StatisticsOps},
    Confidence, Interval,
};
use std::path::Path;
use strum::IntoEnumIterator;
use tokio::io;

const ITERATION_COUNT: usize = 100;
const CONFIDENCE_LEVEL: f64 = 0.95;

fn get_statiscal_analysis_results(data: Vec<f32>) -> (f32, f32, Interval<f32>) {
    // The confidence instance
    let confidence: Confidence = Confidence::new(CONFIDENCE_LEVEL);

    // The statistical analysis instance
    let mut arithmetic_data: Arithmetic<f32> = Arithmetic::new();

    // Append the data
    arithmetic_data.extend(&data).unwrap();

    // Compute the average or mean
    let average: f32 = arithmetic_data.sample_mean();

    // Compute the standard deviation
    let standard_deviation: f32 = arithmetic_data.sample_std_dev();

    // Compute the confidence_interval
    let confidence_interval: Interval<f32> = arithmetic_data.ci_mean(confidence).unwrap();

    (average, standard_deviation, confidence_interval)
}

fn print_output(
    average_time_client: f32,
    standard_deviation_client: f32,
    confidence_interval_client: Interval<f32>,
    communication_cost_client: usize,
    average_time_server: f32,
    standard_deviation_server: f32,
    confidence_interval_server: Interval<f32>,
    communication_cost_server: usize,
) {
    println!(
        "\x1b[94m\t Client's average execution time: {:.3} milliseconds \x1b[0m",
        average_time_client * 1000.0
    );
    println!(
        "\x1b[95m\t Standard deviation of client execution times: {:.3} \x1b[0m",
        standard_deviation_client * 1000.0
    );
    println!(
        "\x1b[96m\t {}% Confidence interval of client execution times: [{:.3}, {:.3}] \x1b[0m",
        (CONFIDENCE_LEVEL * 100.0),
        confidence_interval_client.low().unwrap() * 1000.0,
        confidence_interval_client.high().unwrap() * 1000.0
    );
    println!(
        "\x1b[97m\t Client's fixed communication cost: {} bytes \x1b[0m\n",
        communication_cost_client
    );

    println!(
        "\x1b[94m\t Server's average execution time: {:.3} milliseconds \x1b[0m",
        average_time_server * 1000.0
    );
    println!(
        "\x1b[95m\t Standard deviation of server execution times: {:.3} \x1b[0m",
        standard_deviation_server * 1000.0
    );
    println!(
        "\x1b[96m\t {}% Confidence interval of server execution times: [{:.3}, {:.3}] \x1b[0m",
        (CONFIDENCE_LEVEL * 100.0),
        confidence_interval_server.low().unwrap() * 1000.0,
        confidence_interval_server.high().unwrap() * 1000.0
    );
    println!(
        "\x1b[97m\t Server's fixed communication cost: {} bytes \x1b[0m\n",
        communication_cost_server
    );
}

fn write_results(
    protocol_variant: &str,
    authenticate: &str,
    average_time_client: f32,
    standard_deviation_client: f32,
    confidence_interval_client: &Interval<f32>,
    communication_cost_client: usize,
    average_time_server: f32,
    standard_deviation_server: f32,
    confidence_interval_server: &Interval<f32>,
    communication_cost_server: usize,
    row: usize,
    worksheet: &mut Worksheet,
) {
    worksheet
        .write_string(row as u32, 0, protocol_variant)
        .unwrap();
    worksheet.write_string(row as u32, 1, authenticate).unwrap();
    worksheet
        .write_string(
            row as u32,
            2,
            &format!("{:.3}", average_time_client * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            3,
            &format!("{:.3}", standard_deviation_client * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            4,
            &format!(
                "[{:.3}, {:.3}]",
                confidence_interval_client.low().unwrap() * 1000.0,
                confidence_interval_client.high().unwrap() * 1000.0
            ),
        )
        .unwrap();
    worksheet
        .write_string(row as u32, 5, &format!("{}", communication_cost_client))
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            6,
            &format!("{:.3}", average_time_server * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            7,
            &format!("{:.3}", standard_deviation_server * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            8,
            &format!(
                "[{:.3}, {:.3}]",
                confidence_interval_server.low().unwrap() * 1000.0,
                confidence_interval_server.high().unwrap() * 1000.0
            ),
        )
        .unwrap();
    worksheet
        .write_string(row as u32, 9, &format!("{}", communication_cost_server))
        .unwrap();
}

async fn register_100_clients(
    protocol_variant: AvailableVariants,
) -> io::Result<Vec<(TkClient, TkServer)>> {
    let mut registered_clients: Vec<(TkClient, TkServer)> = Vec::new();

    for _ in 0..ITERATION_COUNT {
        let client_id: Vec<u8> = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(|c| c as u8)
            .collect();
        let mut client_password: [u8; 32] = [0u8; 32];
        thread_rng().fill(&mut client_password);

        // Doing the one-time client registration of 100 clients
        let (tk_client_instance, tk_server_instance) =
            perform_tk_pake_client_registration(&client_id, &client_password, protocol_variant)
                .await?;
        registered_clients.push((tk_client_instance, tk_server_instance));
    }

    Ok(registered_clients)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut workbook: Workbook = Workbook::new();

    let mut row: usize = 1;

    // Create worksheet and write headers before the loop
    {
        let worksheet: &mut Worksheet = workbook.add_worksheet();
        worksheet.write_string(0, 0, "Protocol Variant").unwrap();
        worksheet.write_string(0, 1, "Authenticate").unwrap();
        worksheet
            .write_string(0, 2, "Client Avg Time (ms)")
            .unwrap();
        worksheet.write_string(0, 3, "Client Std Dev").unwrap();
        worksheet.write_string(0, 4, "Client CI").unwrap();
        worksheet
            .write_string(0, 5, "Client Comm Cost (bytes)")
            .unwrap();
        worksheet
            .write_string(0, 6, "Server Avg Time (ms)")
            .unwrap();
        worksheet.write_string(0, 7, "Server Std Dev").unwrap();
        worksheet.write_string(0, 8, "Server CI").unwrap();
        worksheet
            .write_string(0, 9, "Server Comm Cost (bytes)")
            .unwrap();

        for protocol_variant in AvailableVariants::iter() {
            let registered_clients: Vec<(TkClient, TkServer)> =
                register_100_clients(protocol_variant).await.unwrap();

            println!(
                    "\x1b[93m Benchmarking {:?} variant of TK-PAKE for {} iterations with Client Authentication. \x1b[0m",
                    protocol_variant, ITERATION_COUNT
                );

            let (
                client_execution_times,
                communication_cost_client,
                server_execution_times,
                communication_cost_server,
            ) = execute_tk_pake(registered_clients, true).await?;

            let (average_time_client, standard_deviation_client, confidence_interval_client) =
                get_statiscal_analysis_results(client_execution_times);

            let (average_time_server, standard_deviation_server, confidence_interval_server) =
                get_statiscal_analysis_results(server_execution_times);

            print_output(
                average_time_client,
                standard_deviation_client,
                confidence_interval_client,
                communication_cost_client,
                average_time_server,
                standard_deviation_server,
                confidence_interval_server,
                communication_cost_server,
            );

            write_results(
                &format!("{:?}", protocol_variant),
                "True",
                average_time_client,
                standard_deviation_client,
                &confidence_interval_client,
                communication_cost_client,
                average_time_server,
                standard_deviation_server,
                &confidence_interval_server,
                communication_cost_server,
                row,
                worksheet,
            );
            row += 1;
        }
    }

    // Find a unique filename
    let mut file_index = 0;
    let mut filename = String::from("tk_pake_data_auth.xlsx");
    while Path::new(&filename).exists() {
        file_index += 1;
        filename = format!("tk_pake_data_auth_{}.xlsx", file_index);
    }

    let _ = workbook.save(&filename);
    Ok(())
}
