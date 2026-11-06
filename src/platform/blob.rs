use std::sync::Arc;

use anyhow::{Context, bail};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::prefix::PrefixStore;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload, WriteMultipart};
use url::Url;

const UPLOAD_CHUNK: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct BlobStore {
    inner: Arc<dyn ObjectStore>,
}

impl BlobStore {
    pub fn from_url(url: &str) -> anyhow::Result<Self> {
        let parsed = Url::parse(url).context("ULTRIVLY_STORAGE_URL is not a valid URL")?;
        let inner: Arc<dyn ObjectStore> = match parsed.scheme() {
            "s3" => {
                let s3 = AmazonS3Builder::from_env()
                    .with_url(url)
                    .build()
                    .context("invalid S3 storage configuration")?;
                match parsed.path().trim_matches('/') {
                    "" => Arc::new(s3),
                    prefix => Arc::new(PrefixStore::new(s3, prefix)),
                }
            }
            "file" => {
                let dir = parsed
                    .to_file_path()
                    .map_err(|()| anyhow::anyhow!("file storage URL must be an absolute path"))?;
                Arc::new(LocalFileSystem::new_with_prefix(&dir).with_context(|| {
                    format!("storage directory {} is not usable", dir.display())
                })?)
            }
            "memory" => Arc::new(InMemory::new()),
            other => {
                bail!("unsupported storage scheme {other:?}; use s3://, file://, or memory://")
            }
        };
        Ok(Self { inner })
    }

    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(InMemory::new()),
        }
    }

    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> object_store::Result<()> {
        self.inner
            .put(&Path::from(key), PutPayload::from(bytes))
            .await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> object_store::Result<Vec<u8>> {
        Ok(self
            .inner
            .get(&Path::from(key))
            .await?
            .bytes()
            .await?
            .to_vec())
    }

    pub async fn exists(&self, key: &str) -> object_store::Result<bool> {
        match self.inner.head(&Path::from(key)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn delete(&self, key: &str) -> object_store::Result<()> {
        match self.inner.delete(&Path::from(key)).await {
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            result => result,
        }
    }

    pub async fn delete_prefix(&self, prefix: &str) -> object_store::Result<()> {
        let locations = self
            .inner
            .list(Some(&Path::from(prefix)))
            .map_ok(|meta| meta.location)
            .boxed();
        let mut results = self.inner.delete_stream(locations);
        while let Some(result) = results.next().await {
            match result {
                Ok(_) | Err(object_store::Error::NotFound { .. }) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub async fn put_file(&self, key: &str, path: &std::path::Path) -> anyhow::Result<u64> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let upload = self.inner.put_multipart(&Path::from(key)).await?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, UPLOAD_CHUNK);
        let mut buffer = vec![0; UPLOAD_CHUNK];
        let mut total = 0u64;
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(err) => {
                    let _ = writer.abort().await;
                    return Err(err.into());
                }
            };
            total += read as u64;
            writer.wait_for_capacity(4).await?;
            writer.write(&buffer[..read]);
        }
        writer.finish().await?;
        Ok(total)
    }

    pub async fn stream(
        &self,
        key: &str,
    ) -> object_store::Result<(u64, BoxStream<'static, object_store::Result<Bytes>>)> {
        let result = self.inner.get(&Path::from(key)).await?;
        Ok((result.meta.size, result.into_stream()))
    }
}
