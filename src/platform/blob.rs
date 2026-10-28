










use std::sync::Arc;

use anyhow::{Context, bail};
use futures::{StreamExt, TryStreamExt};
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::memory::InMemory;
use object_store::path::Path;
use object_store::prefix::PrefixStore;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use url::Url;

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
}
