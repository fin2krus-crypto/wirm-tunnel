CUR=$(pwd)
if [ -d "/root/git/wirm-tunnel/.git" ] && [ "$CUR" != "/root/git/wirm-tunnel" ]; then
    tar --exclude=.git -cf - . | tar -xf - -C /root/git/wirm-tunnel
    cd /root/git/wirm-tunnel
elif [ ! -d ".git" ]; then
    rm -rf /tmp/wirm_push
    git clone https://github.com/n0nam4ik/wirm-tunnel.git /tmp/wirm_push
    tar --exclude=.git -cf - . | tar -xf - -C /tmp/wirm_push
    cd /tmp/wirm_push
fi

git status -s
git add -A
git commit -m "Release v0.4.2: chunked Send (40+ Mbps), 1ms batcher, 4MB gVisor buffers, Android paste buttons"
git push origin main