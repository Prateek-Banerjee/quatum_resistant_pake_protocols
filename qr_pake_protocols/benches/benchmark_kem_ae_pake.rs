use qr_pake_protocol_executors::bench_api::kem_ae_pake::{
    execute_kem_ae_pake, perform_kem_ae_pake_client_registration,
};
use qr_pake_protocols::{AvailableVariants, KemAeClient, KemAeServer};
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

/// Performs statistical analysis on a dataset of `f32` values.
///
/// # Parameters:
/// - `data`: `Vec<f32>` - The dataset to analyze.
///
/// # Returns:
/// - `(f32, f32, Interval<f32>)`: A tuple containing the average (mean), standard deviation,
/// and confidence interval of the data.
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

/// Prints formatted benchmark results for client and server execution times and communication costs.
///
/// # Parameters:
/// - `average_time_client`: `f32` - Average execution time of the client in seconds.
/// - `standard_deviation_client`: `f32` - Standard deviation of the client execution times in seconds.
/// - `confidence_interval_client`: `Interval<f32>` - Confidence interval for the client execution times.
/// - `communication_cost_client`: `usize` - Fixed communication cost for the client in bytes.
/// - `average_time_server`: `f32` - Average execution time of the server in seconds.
/// - `standard_deviation_server`: `f32` - Standard deviation of the server execution times in seconds.
/// - `confidence_interval_server`: `Interval<f32>` - Confidence interval for the server execution times.
/// - `communication_cost_server`: `usize` - Fixed communication cost for the server in bytes.
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
    worksheet
        .write_string(
            row as u32,
            1,
            &format!("{:.3}", average_time_client * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            2,
            &format!("{:.3}", standard_deviation_client * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            3,
            &format!(
                "[{:.3}, {:.3}]",
                confidence_interval_client.low().unwrap() * 1000.0,
                confidence_interval_client.high().unwrap() * 1000.0
            ),
        )
        .unwrap();
    worksheet
        .write_string(row as u32, 4, &format!("{}", communication_cost_client))
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            5,
            &format!("{:.3}", average_time_server * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            6,
            &format!("{:.3}", standard_deviation_server * 1000.0),
        )
        .unwrap();
    worksheet
        .write_string(
            row as u32,
            7,
            &format!(
                "[{:.3}, {:.3}]",
                confidence_interval_server.low().unwrap() * 1000.0,
                confidence_interval_server.high().unwrap() * 1000.0
            ),
        )
        .unwrap();
    worksheet
        .write_string(row as u32, 8, &format!("{}", communication_cost_server))
        .unwrap();
}

async fn register_100_clients(
    protocol_variant: AvailableVariants,
) -> io::Result<Vec<(KemAeClient, KemAeServer)>> {
    let mut registered_clients: Vec<(KemAeClient, KemAeServer)> = Vec::new();

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
            perform_kem_ae_pake_client_registration(&client_id, &client_password, protocol_variant)
                .await?;
        registered_clients.push((tk_client_instance, tk_server_instance));
    }

    Ok(registered_clients)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Create a new workbook and worksheet
    let mut workbook: Workbook = Workbook::new();
    let mut worksheet: &mut Worksheet = workbook.add_worksheet();

    // Write headers
    worksheet.write_string(0, 0, "Protocol Variant").unwrap();
    worksheet
        .write_string(0, 1, "Client Avg Time (ms)")
        .unwrap();
    worksheet.write_string(0, 2, "Client Std Dev").unwrap();
    worksheet.write_string(0, 3, "Client CI").unwrap();
    worksheet
        .write_string(0, 4, "Client Comm Cost (bytes)")
        .unwrap();
    worksheet
        .write_string(0, 5, "Server Avg Time (ms)")
        .unwrap();
    worksheet.write_string(0, 6, "Server Std Dev").unwrap();
    worksheet.write_string(0, 7, "Server CI").unwrap();
    worksheet
        .write_string(0, 8, "Server Comm Cost (bytes)")
        .unwrap();

    let mut row: usize = 1;

    for protocol_variant in AvailableVariants::iter() {
        let registered_clients: Vec<(KemAeClient, KemAeServer)> =
            register_100_clients(protocol_variant).await.unwrap();

        println!(
            "\x1b[93m Benchmarking {:?} variant of KEM-AE-PAKE for {} iterations. \x1b[0m",
            protocol_variant, ITERATION_COUNT
        );

        // Benchmarking
        let (
            client_execution_times,
            communication_cost_client,
            server_execution_times,
            communication_cost_server,
        ) = execute_kem_ae_pake(registered_clients).await?;

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

        // Write results to Excel
        write_results(
            &format!("{:?}", protocol_variant),
            average_time_client,
            standard_deviation_client,
            &confidence_interval_client,
            communication_cost_client,
            average_time_server,
            standard_deviation_server,
            &confidence_interval_server,
            communication_cost_server,
            row,
            &mut worksheet,
        );
        row += 1;
    }

    // Find a unique filename
    let mut file_index = 0;
    let mut filename = String::from("kemae_pake_data.xlsx");
    while Path::new(&filename).exists() {
        file_index += 1;
        filename = format!("kemae_pake_data_{}.xlsx", file_index);
    }

    let _ = workbook.save(&filename);
    Ok(())
}
