# Deployment — Railway (Worker + API tek servis, MVP)

Not: Bu adımları sizin yerinize otomatik yapamıyorum — Railway hesabı, GitHub
bağlantısı ve API key girişi sizin tarafınızda, tarayıcı üzerinden yapılması
gereken işlemler. Aşağıda tam olarak ne tıklayacağınızı adım adım yazıyorum.

## 1. Kod bir Git reposuna gitmeli

Bu `service/` klasörünü (ve bir üst dizindeki `schema/`, `prototype/`, `worker/`
klasörlerini de isterseniz) bir GitHub reposuna push edin. Railway GitHub
reposundan otomatik deploy ediyor.

```bash
git init
git add .
git commit -m "Faz 0-1: schema + extraction service"
git remote add origin <sizin-repo-url>
git push -u origin main
```

## 2. Railway'de proje oluşturma

1. https://railway.app → **New Project** → **Deploy from GitHub repo**
2. Reponuzu seçin, root directory olarak `service/` klasörünü belirtin
   (Railway "Root Directory" ayarı — Settings > General).
3. Railway Dockerfile'ı otomatik algılayacak (repo'da `Dockerfile` var).

## 3. Postgres ekleme

1. Aynı Railway projesinde **+ New** → **Database** → **Add PostgreSQL**
2. Railway otomatik olarak `DATABASE_URL` değişkenini üretir ve panelde gösterir.
3. Bu `DATABASE_URL`'i servisin **Variables** sekmesine ekleyin (Railway bazen
   otomatik bağlar, bağlamazsa manuel referans verin: `${{Postgres.DATABASE_URL}}`).

## 4. Şemayı Postgres'e yükleme

Railway Postgres panelinde **Connect** → verilen `psql` komutunu kendi
terminalinizde çalıştırın (veya TablePlus/DBeaver gibi bir GUI ile bağlanın),
sonra:

```bash
psql "<railway-postgres-connection-string>" -f schema/001_init_schema.sql
```

Bu adımı ben sizin için çalıştıramıyorum çünkü bu sandbox'ın internet erişimi
yok ve Railway kimlik bilgileriniz bende değil.

## 5. Environment variable'ları girme

Servisin **Variables** sekmesinde `.env.example` dosyasındaki tüm değişkenleri
girin. En kritik olanı:

- `ANTHROPIC_API_KEY` → https://console.anthropic.com/settings/keys üzerinden
  yeni bir key oluşturun (Console hesabınız yoksa önce bir tane açmanız gerekir).
- `DATABASE_URL` → adım 3'te Railway'in verdiği değer.

## 6. Deploy

Variable'ları kaydettiğinizde Railway otomatik olarak yeniden deploy eder.
**Deployments** sekmesinden build loglarını izleyin. Hata olursa log'u bana
yapıştırın, birlikte bakarız — ben build'i burada tekrar çalıştıramam ama
hatayı okuyup kodu düzeltebilirim.

## 7. Test

Deploy tamamlanınca Railway size bir public URL verir (Settings > Networking
> Generate Domain). Test edin:

```bash
curl https://<railway-url>/health
# {"status": "ok"}
```

Bir restoran ve menü yüklemek için önce `restaurants` tablosuna elle bir satır
eklemeniz gerekiyor (dashboard/upload UI'ı henüz yok, bu Faz 4'te gelecek):

```sql
insert into restaurant_brands (id, name) values (gen_random_uuid(), 'Test Brand');
-- dönen id'yi kullanarak:
insert into restaurants (id, brand_id, name) values (gen_random_uuid(), '<brand_id>', 'Test Restoran');
```

Sonra:

```bash
curl -X POST https://<railway-url>/restaurants/<restaurant_id>/menus \
  -F "file=@Big_Chefs_Menü.pdf"
```

Dönen `menu_id` ile durumu takip edin:

```bash
curl https://<railway-url>/menus/<menu_id>/status
```

`status: completed` olduğunda `menu_item_ingredients` tablosunu sorgulayarak
gerçek PDF'in gerçek Claude API ile extract edildiğini görebilirsiniz.

## Bilinen MVP sınırlamaları (bilerek basitleştirdim, ileride düzeltilecek)

- **Dosya depolama:** PDF'ler şu an container'ın yerel diskine yazılıyor.
  Railway container'ı yeniden deploy olursa disk sıfırlanır — yani sadece
  test için uygun. Production'a geçmeden önce Supabase Storage/S3'e taşınmalı.
- **Worker aynı process'te:** Ölçek arttıkça (çok sayıda eşzamanlı menü
  yüklemesi) worker'ı ayrı bir servise çıkarmak gerekecek — bunun için önce
  dosya depolamayı obje storage'a taşımak şart (yukarıdaki not).
- **Normalization basit lookup:** `find_or_create_ingredient` şu an pgvector
  embedding similarity kullanmıyor, sadece exact alias lookup yapıyor. Bu,
  tasarım dokümanındaki madde 6'nın basitleştirilmiş bir versiyonu — ilk
  gerçek testlerde yeterli olur ama alias tablosu büyüdükçe embedding
  similarity eklenmeli (sıradaki adımlardan biri olarak öneririm).
- **Vision fallback yok:** Metin katmanı olmayan (taranmış) sayfalar şu an
  atlanıyor. Menülerinizin çoğu text-layer içeriyorsa (kontrol ettim, üçü de
  içeriyor) bu MVP için sorun değil.
