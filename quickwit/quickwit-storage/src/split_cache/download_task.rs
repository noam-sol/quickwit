// Copyright 2021-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use quickwit_common::split_file;
use quickwit_config::StorageCredentials;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::split_cache::split_table::{CandidateSplit, DownloadOpportunity};
use crate::{SplitCache, StorageResolver, StorageUsage};

async fn download_split(
    split_cache: &SplitCache,
    candidate_split: &CandidateSplit,
    storage_resolver: StorageResolver,
) -> anyhow::Result<u64> {
    let CandidateSplit {
        split_ulid,
        storage_uri,
        living_token: _,
        index_id,
    } = candidate_split;

    let split_filename = split_file(*split_ulid);
    let target_filepath = split_cache.root_path.join(&split_filename);

    let storage_credentials = split_cache
        .get_index_storage_credentials(index_id)
        .await
        .unwrap_or_else(|err| {
            tracing::error!(
                index_id = %index_id,
                error = %err,
                "Failed to fetch index-specific credentials, using default credentials"
            );
            StorageCredentials::default()
        });

    let storage = storage_resolver
        .resolve(storage_uri, &storage_credentials, StorageUsage::Index)
        .await?;
    let num_bytes = storage
        .copy_to_file(Path::new(&split_filename), &target_filepath)
        .await?;
    Ok(num_bytes)
}

async fn perform_eviction_and_download(
    download_opportunity: DownloadOpportunity,
    split_cache: Arc<SplitCache>,
    storage_resolver: StorageResolver,
    _download_permit: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let DownloadOpportunity {
        splits_to_delete,
        split_to_download,
    } = download_opportunity;
    let split_ulid = split_to_download.split_ulid;
    let index_id = split_to_download.index_id.clone();

    // tokio io runs on `spawn_blocking` threads anyway.
    let split_cache_clone = split_cache.clone();
    let _ = tokio::task::spawn_blocking(move || {
        split_cache_clone.evict(&splits_to_delete[..]);
    })
    .await;

    let num_bytes = download_split(&split_cache, &split_to_download, storage_resolver).await?;

    let mut split_to_index_map = split_cache.split_to_index_map.lock().unwrap();
    split_to_index_map.insert(split_ulid, index_id);

    let mut shared_split_table_lock = split_cache.split_table.lock().unwrap();
    shared_split_table_lock.register_as_downloaded(split_ulid, num_bytes);
    Ok(())
}

pub(crate) fn spawn_download_task(
    split_cache: Arc<SplitCache>,
    storage_resolver: StorageResolver,
    num_concurrent_downloads: NonZeroU32,
) {
    let semaphore = Arc::new(Semaphore::new(num_concurrent_downloads.get() as usize));
    tokio::task::spawn(async move {
        loop {
            let download_permit = Semaphore::acquire_owned(semaphore.clone()).await.unwrap();
            let download_opportunity_opt = split_cache
                .split_table
                .lock()
                .unwrap()
                .find_download_opportunity();
            if let Some(download_opportunity) = download_opportunity_opt {
                let split_cache_clone = split_cache.clone();
                tokio::task::spawn(perform_eviction_and_download(
                    download_opportunity,
                    split_cache_clone,
                    storage_resolver.clone(),
                    download_permit,
                ));
            } else {
                // We wait 1 sec before retrying, to avoid wasting CPU.
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });
}
