namespace SupersocksR.Net
{
    using System;
    using SupersocksR.Net.Entry;

    public class SocketScheduler
    {
        public ILayerLocator Locator { get; }

        public SocketScheduler(ILayerLocator locator)
        {
            this.Locator = locator ?? throw new ArgumentNullException(nameof(locator));
        }

        public virtual bool BeginAccept(IPcb pcb)
        {
            return pcb != null;
        }

        public virtual Socket EndAccept(IPcb pcb)
        {
            return CreateSocket(pcb);
        }

        protected virtual Socket CreateSocket(IPcb pcb)
        {
            if (pcb == null)
            {
                return null;
            }

            return new Socket(pcb);
        }
    }
}
